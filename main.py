import os
import sys
from configparser import ConfigParser, SectionProxy
from pathlib import Path
from tkinter import Tk
from tkinter.filedialog import askdirectory
from tkinter.messagebox import askyesno
from typing import Dict, List, Union
from FileMove import RecvProcess, SendProcess
from NetIO import NetIO, LOG, pretty_byecount


PROCESS_COUNT = 4
THREAD_COUNT = 4


class Config:
    ip: str
    port: int
    key: str

    def __init__(self, sp: SectionProxy) -> None:
        self.ip = sp["ip"]
        self.port = int(sp["port"])
        self.key = sp["key"]


def run_server(config: Config) -> None:
    """Run server core communication mainloop

    Args:
        config (Config): connection configuration
    """
    client = NetIO.accept(config.ip, config.port, config.key)
    LOG.info(f"Successfully connected with {config.ip}:{config.port}")
    initTkinter()
    while (meta := client.recvM()) and meta.paths is not None:
        if askyesno(
            "Incomeing files",
            f"You have {len(meta.paths)} ({pretty_byecount(sum(meta.paths.values()))}) incomeing files. Do you want to save them?\n"
            + "\n".join([x for i, x in enumerate(meta.paths.keys()) if i < 15]),
        ):
            incomeing_paths: Dict[str, int] = meta.paths
            if root_dir := askdirectory(
                title="Select destination directory for files", initialdir="/"
            ):
                client.sendM(accept=True)
                try:
                    batch_recv_files(config, client, meta.paths, root_dir)
                finally:
                    validate_recved(incomeing_paths, root_dir)
        else:
            client.sendM(accept=False)


def validate_recved(incomeing_paths, root_dir):
    for relapth, size in incomeing_paths.items():
        real_size = os.path.getsize(Path(root_dir, relapth))
        if real_size != size:
            LOG.critical(
                f"Cloning of {relapth} probalby failed as it's size is {pretty_byecount(real_size)} instead of {pretty_byecount(size)} ({pretty_byecount(size-real_size)} difference)"
            )
        else:
            LOG.info(
                f"Successfully cloned {relapth} with all it's contents ({pretty_byecount(real_size)}/{pretty_byecount(size)})"
            )


def batch_recv_files(
    config: Config,
    client: NetIO,
    paths: Dict[str, int],
    root_dir: Union[str, Path],
):
    """Schedule a batch file receiving process

    Args:
        config (Config): connection configuration
        client (NetIO): main communication NetIO object
        meta (Metadata): metadata object containing path dictionary
        root_dir ([type]): [description]
    """
    tasks = [dict() for _ in range(PROCESS_COUNT)]
    for i, key in enumerate(paths.keys()):
        tasks[i % PROCESS_COUNT][key] = paths[key]
    processes: List[RecvProcess] = []
    for i in range(PROCESS_COUNT):
        processes.append(
            RecvProcess(
                root_dir,
                tasks[i],
                config.ip,
                config.port + 1 + THREAD_COUNT * i,
                config.key,
                timeout=None,
                thread_count=THREAD_COUNT,
            )
        )
        processes[-1].start()
    client.sendM(ready=True)
    for p in processes:
        p.join()


def run_client(config: Config) -> None:
    """Start client main process with its mainloop

    Args:
        config (Config): connection configuration
    """
    server = NetIO.connect(config.ip, config.port, config.key)
    LOG.info(f"Successfully connected to {config.ip}:{config.port}")
    initTkinter()
    while root_dir := askdirectory(title="Select directory to clone", initialdir="/"):
        paths: Dict[str:int] = {
            str(Path(path).relative_to(root_dir)): os.path.getsize(path)
            for path in Path(root_dir).glob("**/*")
            if Path(path).is_file()
        }
        server.sendM(paths=paths)
        server.socket.settimeout(None)
        if (meta := server.recvM()) and meta.accept:
            tasks: List[Dict[str, int]] = [dict() for _ in range(PROCESS_COUNT)]
            for i, key in enumerate(paths.keys()):
                tasks[i % PROCESS_COUNT][key] = paths[key]
            if (meta := server.recvM()) and meta.ready:
                batch_send_files(config, root_dir, tasks)
            else:
                LOG.critical(
                    "Failed to send any data to server due to its unready state"
                )
    else:
        server.sendM(paths=None)


def initTkinter() -> Tk:
    """Initialize tkinter root, make it topmost and withdraw it."""
    root = Tk()
    root.wm_attributes("-topmost", 1)
    root.withdraw()
    return root


def batch_send_files(
    config: Config,
    root_dir: Union[Path, str],
    tasks: List[Dict[str, int]],
):
    """Schedule file sending processes, they will
    take up ports from config.port up to
    config.port + 1 + THREAD_COUNT * PROCESS_COUNT

    Args:
        config ([type]): connection configuration
        root_dir (Union[Path, str]): file paths root directory
        tasks (List[Dict[str, int]]): list of dictionatries of tasks to be given to threads
    """
    processes: List[SendProcess] = []
    for i in range(PROCESS_COUNT):
        processes.append(
            SendProcess(
                root_dir,
                tasks[i],
                config.ip,
                config.port + 1 + THREAD_COUNT * i,
                config.key,
                timeout=None,
                thread_count=THREAD_COUNT,
            )
        )
        processes[-1].start()
    for p in processes:
        p.join()


def getConfig(source: Union[str, Path]) -> Config:
    """Create default configuration and update it with
    data fetched from local ini file.

    Args:
        source (Union[str, Path]): path to source *.ini file

    Returns:
        Config: Ready to use configuration
    """
    config = ConfigParser()
    config["Aniotransfer"] = {
        "ip": "0.0.0.0",
        "port": 8888,
        "key": "FDSAF82w34yuf78932hsdfkj2348",
    }
    config.read(source)
    with open(source, "w") as file:
        config.write(file)
    return Config(config["Aniotransfer"])


if __name__ == "__main__":
    import argparse

    def parseArgv(src: List[str]) -> argparse.Namespace:
        parser = argparse.ArgumentParser()
        parser.add_argument("program", type=str, help="Python script path")
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "--test",
            "-t",
            action="store_true",
            default=False,
            help="Run doctests and exit",
        )
        group.add_argument(
            "--server",
            "-s",
            action="store_true",
            default=False,
            help="Run script as a server",
        )
        group.add_argument(
            "--client",
            "-c",
            action="store_true",
            default=False,
            help="Run script as a client",
        )
        parser.add_argument(
            "--loglvl",
            choices=("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"),
            default="WARNING",
            type=lambda s: s.upper(),
            help="Logging level",
        )
        return parser.parse_args(src)

    argv = parseArgv(sys.argv)
    LOG.setLevel(argv.loglvl)
    LOG.debug(f"Arguments received: {argv}")
    if argv.test:
        LOG.debug("Selected doctest mode, running doctests")
        import doctest

        doctest.testmod(verbose=argv.loglvl == "DEBUG")
    elif argv.server:
        run_server(getConfig("./config.ini"))
    elif argv.client:
        run_client(getConfig("./config.ini"))
    else:
        exit(-1)
