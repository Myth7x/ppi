import json

import pydivert
import time
from fastapi import FastAPI
from uvicorn import run
from threading import Thread
from fastapi.middleware.cors import CORSMiddleware
import logging


class Sniffer(object):
    def __init__(self):
        self.logger = logging.getLogger("Sniffer")
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(logging.StreamHandler())
        self._enabled = False
        self._force_stop = False
        self._rules = []
        self._packet_log = []
        self._filter = "tcp.DstPort == 10375 or tcp.SrcPort == 10375"

    # properties
    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        self._enabled = value

    @property
    def force_stop(self) -> bool:
        return self._force_stop

    @force_stop.setter
    def force_stop(self, value: bool):
        self._force_stop = value

    @property
    def rules(self) -> list:
        return self._rules

    @rules.setter
    def rules(self, value: list):
        self._rules = value

    @property
    def packet_log(self) -> list:
        return self._packet_log

    @packet_log.setter
    def packet_log(self, value: list):
        self._packet_log = value

    @property
    def filter(self) -> str:
        return self._filter

    @filter.setter
    def filter(self, value: str):
        self._filter = value

    # methods
    def set_enabled(self) -> None:
        """
        This will enable the sniffer.
        :return:
        """
        self.enabled = True
        self.force_stop = False

    def set_disabled(self) -> None:
        """
        This will disable the sniffer.
        :return:
        """
        self.enabled = False
        self.force_stop = True

    def run(self) -> None:
        """
        This is the main loop for the sniffer.

        Todo:
            - Add description for this method.
        :return:
        """
        self.logger.info(f"<Sniffer> Starting sniffer with filter: {self._filter}")
        with pydivert.WinDivert(self._filter) as wd:
            while True:
                for packet in wd:

                    if not self._enabled:
                        wd.send(packet)
                        continue

                    if self._force_stop:
                        self.logger.info("<Sniffer> Received stop signal, sending remaining packets.")
                        # make sure to send every last packet, before closing the connection
                        while True:
                            try:
                                wd.send(packet)
                            except:
                                break
                        wd.close()
                        self.force_stop = False
                        self.logger.info("<Sniffer> Sniffer stopped.")
                        return

                    setattr(packet, 'timestamp', time.time())
                    self._packet_log.append(packet)
                    wd.send(packet)


class CtlAPI(FastAPI):


    # noinspection PyTypeChecker
    def __init__(self, sniffer: Sniffer):
        super().__init__(port=5001)
        self._sniffer = sniffer
        self.logger = logging.getLogger("CtlAPI")
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(logging.StreamHandler())
        self.t_sniffer = None

        self.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            allow_origin_regex="https?://.*",
            expose_headers=["*"],
        )

        self.add_api_route("/", self.all_routes, methods=["POST", "GET"])

        self.add_api_route("/get_status", self.get_status, methods=["POST", "GET"])

        self.add_api_route("/enable", self.enable_sniffer, methods=["POST", "GET"])
        self.add_api_route("/disable", self.disable_sniffer, methods=["POST", "GET"])

        self.add_api_route("/get_sniffer_filter", self.get_sniffer_filter, methods=["POST", "GET"])
        self.add_api_route("/set_sniffer_filter", self.set_sniffer_filter, methods=["POST", "GET"])

        self.add_api_route("/ws_packet_log", self.ws_packet_log, methods=["POST", "GET"])



    def restart_sniffer(self) -> None:
        """
        This will restart the sniffer.
        :return:
        """
        self.logger.info("<Sniffer> Restarting sniffer.")
        self.disable_sniffer()
        wait_time = 0
        while self.t_sniffer.is_alive():
            self.logger.info("<Sniffer> Waiting for sniffer to stop.")
            if not self.t_sniffer.is_alive():
                break
            time.sleep(0.5)
            wait_time += 0.5
            if wait_time >= 5:
                self.logger.info("<Sniffer> Sniffer did not stop in time, forcing stop.")
                self._sniffer.force_stop = True
                break
        self.enable_sniffer()
        self.logger.info("<Sniffer> Sniffer restarted.")

    def get_sniffer_filter(self) -> dict:
        return {'filter': self._sniffer.filter}

    def set_sniffer_filter(self, filter: str) -> dict:
        self.logger.info(f"<Sniffer> Setting sniffer({self._sniffer.filter}) filter to: {filter}")
        self._sniffer.filter = filter
        if self._sniffer.enabled:
            self.logger.info("<Sniffer> Sniffer is enabled, restarting..")
            self.restart_sniffer()
        self.logger.info(f"<Sniffer> Sniffer filter set. (self(enabled({self._sniffer.enabled}), filter({self._sniffer.filter})))")
        return {'status': 'enabled' if self._sniffer.enabled else 'disabled'}

    def ws_packet_log(self) -> dict:
        _l = [
            {
                'timestamp': packet.timestamp,
                'src_addr': packet.src_addr,
                'dst_addr': packet.dst_addr,
                'payload': packet.payload.hex()
            } for packet in sorted(self._sniffer.packet_log, key=lambda x: x.timestamp, reverse=False)
        ]
        self._sniffer.packet_log = []
        return {'list': _l}

    def all_routes(self) -> dict:
        return {'list': [{'url': route.path, 'methods': route.methods} for route in self.routes]}

    def get_status(self) -> dict:
        return {"status": "enabled" if self._sniffer.enabled else "disabled"}

    def enable_sniffer(self) -> dict:
        self._sniffer.set_enabled()
        self.t_sniffer = Thread(target=self._sniffer.run, daemon=True)
        self.t_sniffer.start()
        return {"status": "enabled"}

    def disable_sniffer(self) -> dict:
        self._sniffer.set_disabled()
        return {"status": "disabled"}


def create_sniffer() -> CtlAPI:
    sniffer = Sniffer()
    app = CtlAPI(sniffer)
    app.t_sniffer = Thread(target=run, args=(app,), kwargs={"host": "0.0.0.0", "port": 5001})
    app.t_sniffer.start()
    return app
