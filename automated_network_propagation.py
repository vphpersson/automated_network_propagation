#!/usr/bin/env python

from logging import getLogger, Logger, INFO
from logging.handlers import TimedRotatingFileHandler
from asyncio import Queue, CancelledError
from typing import Final
from contextlib import suppress
from json import dumps as json_dumps
from weakref import WeakSet

from ecs_tools_py import make_log_handler
from aiohttp.web import Application, run_app, Request, Response
from aiohttp_sse import sse_response, EventSourceResponse

from automated_network_propagation.cli import AutomatedNetworkPropagationOptionParser as ANPOP

LOG: Final[Logger] = getLogger(__name__)


async def feed(request: Request):

    queue = Queue()
    request.app.connections.add(queue)

    with suppress(CancelledError, ConnectionResetError):
        response: EventSourceResponse
        async with sse_response(request) as response:
            data_tuple: tuple[str, str]
            while data_tuple := await queue.get():
                event, data = data_tuple
                await response.send(data=data, event=event)

    # NOTE: Not convinced by this.
    return response


async def submit(request: Request):

    data: dict[str, ...] = await request.json()

    if '@timestamp' in data:
        if 'source' in data and 'ip' in data['source']:
            ip_address = data['source']['ip']
        elif 'client' in data and 'ip' in data['client']:
            ip_address = data['client']['ip']
        else:
            # TODO: What to include in `extra`?
            # TODO: Do mapping; `rule` fields, unique WAF id.
            LOG.warning(
                msg='No IP address is presented in a submitted alert document.'
            )
            return Response(status=400)

        for queue in request.app.connections:
            await queue.put(('block', ip_address))

        return Response()
    elif 'type' in data:
        for queue in request.app.connections:
            await queue.put((data['type'], json_dumps(data)))
        return Response()
    else:
        return Response(status=400)


def main():
    try:
        args: ANPOP.Namespace = ANPOP().parse_options(read_config=False)

        log_handler = make_log_handler(
            base_class=TimedRotatingFileHandler,
            provider_name='automated_network_propagation_server',
            generate_field_names=('event.timezone', 'host.name', 'host.hostname')
        )(filename=args.log_path, when='D')

        LOG.addHandler(hdlr=log_handler)
        LOG.setLevel(level=INFO)

        app = Application()
        app.connections = WeakSet()

        app.router.add_route('POST', '/submit', submit)
        app.router.add_route('GET', '/feed', feed)

        run_app(app, host=args.host, port=args.port)
    except KeyboardInterrupt:
        pass
    except Exception:
        LOG.exception(msg='An unexpected error occurred.')


if __name__ == '__main__':
    main()
