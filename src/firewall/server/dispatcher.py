# SPDX-License-Identifier: GPL-2.0-or-later

from gi.repository import GLib

import os

from firewall.core.logger import log
from firewall.config import FIREWALLD_DISPATCHER, ETC_FIREWALLD_DISPATCHER, COMMANDS


def handle_completion(pid, status, data):
    log.debug1(
        f"dispatcher completion handler for file: '{data[0]} interface: '{data[1]}' signal: {data[2]}."
    )
    try:
        GLib.spawn_check_exit_status(status)
    except GLib.GError:
        log.debug1(
            f"error running dispatcher for file: '{data[0]} interface: '{data[1]}' signal: {data[2]}."
        )
    GLib.spawn_close_pid(pid)


def run_dispatcher(interface, signal, args):
    def _dispatchers(directories):
        for directory in directories:
            if not os.path.isdir(directory):
                continue
            for file in os.listdir(directory):
                _path = os.path.abspath(directory + os.sep + file)
                if os.path.isfile(_path) and os.access(_path, os.X_OK):
                    yield _path

    environment = ["LANG=C", "LANGUAGE=C", "LC_ALL=C", "LC_MESSAGES=C"]
    executor = [COMMANDS["systemd-run"], "--no-block", "--property", "TimeoutSec=60"]
    arguments = [interface, signal] + [str(a) for a in args]
    for file in _dispatchers([FIREWALLD_DISPATCHER, ETC_FIREWALLD_DISPATCHER]):
        process_arguments = [file] + arguments
        process = GLib.spawn_async(
            executor + process_arguments,
            envp=environment,
            flags=GLib.SPAWN_DO_NOT_REAP_CHILD,
            standard_output=False,
            standard_error=False,
        )

        GLib.child_watch_add(
            GLib.PRIORITY_DEFAULT, process[0], handle_completion, process_arguments
        )
