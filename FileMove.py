import logging
import os
import socket as so
import sys
from abc import ABC
from io import FileIO
from multiprocessing import Process
from pathlib import Path
from threading import Thread, current_thread
from typing import Dict, List, Tuple

from NetIO import LOG, NetIO, pretty_byecount

DIR_TREE_T = Dict[str, int]


MAX_SEND_SIZE = 8 * 1024 * 1024
MAX_THREAD_COUNT = 3


class RecvTask:
    abspath: Path
    relpath: Path
    size: int
    recv: int
    _file: FileIO

    def __init__(self, root_dir: str, relpath: str, size: int) -> None:
        self.relpath = Path(relpath)
        self.root_dir = root_dir
        self.size = size
        self.recv = 0
        self._file = None

    @property
    def abspath(self) -> Path:
        return Path(self.root_dir, self.relpath)

    def write(self, data: bytes) -> FileIO:
        if not self.isFinished:
            if self._file is None:
                try:
                    os.makedirs(os.path.dirname(self.abspath))
                except:
                    pass
                self._file = open(self.abspath, "wb")
            self._file.write(data)
            self.recv += len(data)
            LOG.info(
                f"Received {pretty_byecount(self.recv)} / {pretty_byecount(self.size)} file `{self.relpath}`"
            )
            if self.isFinished:
                self._file.close()

    @property
    def isFinished(self) -> bool:
        return self.recv == self.size


class RecvProcess(Process):
    def __init__(
        self,
        root_dir: str,
        file_tree: DIR_TREE_T,
        ip: str,
        port: int,
        key: str,
        timeout: float=None,
        *,
        thread_count=MAX_THREAD_COUNT,
    ) -> None:
        super().__init__()
        self.tasks: Dict[str, RecvTask] = {}
        for relpath, size in file_tree.items():
            self.tasks[relpath] = RecvTask(root_dir, relpath, size)
        self.ip = ip
        self.port = port
        self.key = key
        self.timeout = timeout
        self.thread_count = thread_count
        self.finished = {}
        self.fails = 0

    def thread_main(self, io: NetIO, tasks: Dict[str, RecvTask]) -> None:
        LOG.info(
            f"Thread {current_thread().name} has been started with {len(tasks)} tasks of total size of {pretty_byecount(sum(t.size for t in tasks.values()))}"
        )
        fails = 0
        while tasks:
            try:
                mess = io.recv()
                EOF = mess.metadata.EOF
                if mess.metadata.relpath in tasks:
                    task = tasks[mess.metadata.relpath]
                    if EOF:
                        self.finished[mess.metadata.relpath] = tasks.pop(
                            mess.metadata.relpath
                        )
                        LOG.info(
                            f"Finished [EOF] `{task.relpath}` cloned {pretty_byecount(task.recv)} / {pretty_byecount(task.size)}, {len(self.tasks)-len(self.finished)} / {len(self.tasks)} tasks left"
                        )
                    else:
                        task.write(mess.payload.data)
                        if task.isFinished:
                            self.finished[mess.metadata.relpath] = tasks.pop(
                                mess.metadata.relpath
                            )
                            LOG.warning(
                                f"Finished `{task.relpath}` cloned {pretty_byecount(task.recv)} / {pretty_byecount(task.size)}, {len(self.tasks)-len(self.finished)} / {len(self.tasks)} tasks left"
                            )
            except Exception as e:
                fails += 1
        if fails == 0:
            LOG.warning(
                f"Thread {current_thread().name} has finished its work with full success."
            )
        else:
            LOG.warning(
                f"Thread {current_thread().name} finished, but encountered {fails} problems."
            )
        self.fails += fails

    def run(self):
        try:
            self.io = [
                NetIO.accept(self.ip, self.port + i, self.key, timeout=self.timeout)
                for i in range(self.thread_count)
            ]
        except so.timeout:
            logging.critical(
                "Failed to estabilish full connection with client due to socket timeout."
            )
        else:
            self.threads = []
            self.thread_tasks = [{} for _ in range(self.thread_count)]
            i = 0
            for relpath, task in self.tasks.items():
                self.thread_tasks[i % self.thread_count][relpath] = task
                i += 1
            for i in range(self.thread_count):
                self.threads.append(
                    Thread(
                        target=self.thread_main, args=(self.io[i], self.thread_tasks[i])
                    )
                )
                self.threads[-1].start()
            for thd in self.threads:
                thd.join()


class SendTask(Process):
    abspath: Path
    relpath: Path
    root_dir: Path
    size: int
    send: int
    _file: FileIO

    def __init__(self, root_dir: str, relpath: str, size: int) -> None:
        self.root_dir = Path(root_dir)
        self.relpath = Path(relpath)
        self.size = size
        self.send = 0
        self._file = None

    @property
    def abspath(self) -> Path:
        return Path(self.root_dir, self.relpath)

    def read(self) -> bytes:
        if not self.isFinished:
            if self._file is None:
                self._file = open(self.abspath, "rb")
            buffer = self._file.read(MAX_SEND_SIZE)
            self.send += len(buffer)
            if self.isFinished:
                self._file.close()

            return buffer

    @property
    def isFinished(self) -> bool:
        return self.send == self.size


class SendProcess(Process):
    def __init__(
        self,
        root_dir: str,
        file_tree: DIR_TREE_T,
        ip: str,
        port: int,
        key: str,
        timeout: float=None,
        *,
        thread_count=MAX_THREAD_COUNT,
    ) -> None:
        super().__init__()
        self.tasks = []
        for relpath, size in file_tree.items():
            self.tasks.append(SendTask(root_dir, relpath, size))
        self.ip = ip
        self.port = port
        self.key = key
        self.timeout = timeout
        self.thread_count = thread_count
        self.finished = []

    def thread_main(self, io: NetIO, tasks: List[SendTask]) -> None:
        while tasks:
            task = tasks.pop()
            while not task.isFinished:
                io.send({"relpath": str(task.relpath), "EOF": False}, task.read())
            io.send({"relpath": str(task.relpath), "EOF": True})
            LOG.info(
                f"Finished sending `{task.relpath}` with {pretty_byecount(task.send)} / {pretty_byecount(task.size)}"
            )
            self.finished.append(task)

    def run(self):
        self.io = [
            NetIO.connect(self.ip, self.port + i, self.key, timeout=self.timeout)
            for i in range(self.thread_count)
        ]
        self.threads = []
        self.thread_tasks = [[] for _ in range(self.thread_count)]
        i = 0
        for task in self.tasks:
            self.thread_tasks[i % self.thread_count].append(task)
            i += 1
        for i in range(self.thread_count):
            self.threads.append(
                Thread(
                    target=self.thread_main,
                    args=(
                        self.io[i],
                        self.thread_tasks[i],
                    ),
                )
            )
            self.threads[-1].start()
        for thd in self.threads:
            thd.join()


def client_path_tree(root_dir: str) -> Dict[str, int]:
    return {
        str(path.relative_to(root_dir)): os.path.getsize(path)
        for path in Path(root_dir).glob("**/*")
        if path.is_file()
    }


if __name__ == "__main__":
    import argparse

    def parseArgv(src: List[str]) -> argparse.Namespace:
        parser = argparse.ArgumentParser()
        parser.add_argument("program", type=str, help="Python script path")
        # parser.add_argument("ip", type=str, help="Connection IPv4")
        # parser.add_argument("port", type=int, help="Connection port")
        # parser.add_argument("key", type=str, help="Connection key")
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
            "--verbose",
            action="store_true",
            default=False,
            help="Verbose doctests",
        )
        return parser.parse_args(src)

    argv = parseArgv(sys.argv)
    if argv.test:
        import doctest

        doctest.testmod(verbose=argv.verbse)
    elif argv.server:
        root_dir = "./dest"
        tree = client_path_tree(r"D:\Zdjęcia\Ania i Ja")
        P = RecvProcess(
            root_dir,
            tree,
            "192.168.1.154",
            8888,
            "KEY",
            10.0,
        )
        P.start()
        P.join()
    elif argv.client:
        root_dir = r"D:\Zdjęcia\Ania i Ja"
        tree = client_path_tree(r"D:\Zdjęcia\Ania i Ja")
        P = SendProcess(
            root_dir,
            tree,
            "192.168.1.154",
            8888,
            "KEY",
            10.0,
        )
        P.start()
        P.join()
