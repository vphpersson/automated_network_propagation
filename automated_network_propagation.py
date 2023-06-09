#!/usr/bin/env python

from logging import getLogger, Logger, INFO, StreamHandler
from logging.handlers import TimedRotatingFileHandler
from sys import stderr
from dataclasses import dataclass
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


@dataclass(unsafe_hash=True)
class ConnectionData:
    queue: Queue
    client_ip: str | None
    client_port: int | None
    subscriptions: tuple[str, ...] | None


async def feed(request: Request):
    try:
        if isinstance(request._transport_peername, (list, tuple)):
            client_ip, client_port = request._transport_peername
        elif request._transport_peername is not None:
            client_ip = str(request._transport_peername)
            client_port = None
        else:
            client_ip = None
            client_port = None

        if subscription_value := request.rel_url.query.get('subscriptions'):
            subscriptions = tuple(set(subscription_value.split(',')))
        else:
            subscriptions = None

        connection_data = ConnectionData(
            queue=Queue(),
            client_ip=client_ip,
            client_port=client_port,
            subscriptions=subscriptions
        )

        request.app.connections.add(connection_data)
        LOG.info(
            msg='A client was added to the connections',
            extra=dict(
                client_ip=client_ip,
                client_port=client_port,
                subscriptions=subscriptions
            )
        )

        with suppress(CancelledError, ConnectionResetError):
            response: EventSourceResponse
            async with sse_response(request=request) as response:
                data_tuple: tuple[str, str]
                while data_tuple := await connection_data.queue.get():
                    event, data = data_tuple
                    await response.send(data=data, event=event)

        # NOTE: Not convinced by this.
        return response
    except:
        LOG.exception(msg='An unexpected error occurred in feed.')
        return Response(status=500)

async def submit(request: Request):
    try:
        data: dict[str, ...] = await request.json()
        connection_data: ConnectionData

        if '@timestamp' in data:
            if 'source' in data and 'ip' in data['source']:
                ip_address = data['source']['ip']
            elif 'client' in data and 'ip' in data['client']:
                ip_address = data['client']['ip']
            else:
                # TODO: What to include in `extra`?
                # TODO: Do mapping; `rule` fields, unique WAF id.
                LOG.warning(msg='No IP address is presented in a submitted alert document.')
                return Response(status=400)

            for connection_data in request.app.connections:
                if connection_data.subscriptions is None or 'block' in connection_data.subscriptions:
                    await connection_data.queue.put(('block', ip_address))
                    LOG.info(
                        msg='An IP address was was queued',
                        extra=dict(
                            type='block',
                            client_ip=connection_data.client_ip,
                            client_port=connection_data.client_port
                        )
                    )
            return Response()
        elif 'type' in data:
            for connection_data in request.app.connections:
                data_type: str = data['type']
                if connection_data.subscriptions is None or data_type in connection_data.subscriptions:
                    await connection_data.queue.put((data_type, json_dumps(data)))
                    LOG.info(
                        msg='Network data was queued',
                        extra=dict(
                            type=data_type,
                            client_ip=connection_data.client_ip,
                            client_port=connection_data.client_port
                        )
                    )
            return Response()
        else:
            LOG.warning(
                msg='The submitted data is not in the expected format.',
                extra=dict(
                    error=dict(input=await request.text()),
                    _ecs_logger_handler_options=dict(merge_extra=True)
                )
            )
            return Response(status=400)
    except:
        LOG.exception(msg='An unexpected error occurred in submit.')
        return Response(status=500)


def main():
    try:
        args: ANPOP.Namespace = ANPOP().parse_options(read_config=False)

        if args.log_path == '/dev/stderr':
            log_base_class = StreamHandler
            log_args = dict(stream=stderr)
        else:
            log_base_class = TimedRotatingFileHandler
            log_args = dict(filename=args.log_path, when='D')

        log_handler = make_log_handler(
            base_class=log_base_class,
            provider_name='automated_network_propagation_server',
            generate_field_names=('event.timezone', 'host.name', 'host.hostname')
        )(**log_args)

        LOG.addHandler(hdlr=log_handler)
        LOG.setLevel(level=INFO)

        app = Application(client_max_size=16384**2)
        app.connections: WeakSet[ConnectionData] = WeakSet()

        app.router.add_route('POST', '/submit', submit)
        app.router.add_route('GET', '/feed', feed)

        run_app(app, host=args.host, port=args.port)
    except KeyboardInterrupt:
        pass
    except Exception:
        LOG.exception(msg='An unexpected error occurred.')


if __name__ == '__main__':
    main()
