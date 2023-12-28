import fsspec
from fsspec.archive import AbstractArchiveFileSystem
from io import TextIOWrapper

from .pylibsqsh_ext import SqshArchive, SqshFile


class SquashFSFileSystem(AbstractArchiveFileSystem):
    root_marker = ""
    protocol = "squashfs"
    cachable = True

    def __init__(
        self,
        fo="",
        mode="r",
        target_protocol=None,
        target_options=None,
        **kwargs,
    ):
        super().__init__()
        if mode != 'r':
            raise ValueError(f"mode '{mode}' no understood")
        if isinstance(fo, str):
            fo = fsspec.open(
                fo, mode=mode, protocol=target_protocol, **(target_options or {})
            )
        self.of = fo
        self.fo = fo.__enter__()  # the whole instance is a context
        if not isinstance(self.fo, TextIOWrapper):
            raise ValueError("Currently, only files on disks can be read.")
        self.sqshfs = SqshArchive(self.fo.name)

    def __del__(self):
        if hasattr(self, "sqshfs"):
            self.close()
            del self.sqshfs

    def close(self):
        """Commits any write changes to the file. Done on ``del`` too."""
        self.sqshfs.close()

    @classmethod
    def _strip_protocol(cls, path):
        # zip file paths are always relative to the archive root
        return super()._strip_protocol(path).lstrip("/")

    # _get_dirs

    def _open(
        self,
        path: str,
        mode="rb",
        block_size=None,
        autocommit=True,
        cache_options=None,
        **kwargs,
    ) -> SqshFile:
        assert mode in ("rb", "r")
        assert block_size is None
        assert autocommit
        return self.sqshfs.open(path)


def _register():
    fsspec.register_implementation('squashfs', SquashFSFileSystem)
