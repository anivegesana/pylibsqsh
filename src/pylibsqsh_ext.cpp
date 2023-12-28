#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include "sqsh.h"

namespace nb = nanobind;

using namespace nb::literals;

#define PYSQSH_CHECK_CLOSED(fd) if (fd == NULL) { nb::raise("File is already closed!"); }
#define PYSQSH_RAISE(err) { nb::raise("%s", sqsh_error_str(err)); }

class PySqshFile {
    struct SqshFile* subfd;
    friend class PySqshArchive;
    PySqshFile(struct SqshFile* subfd) : subfd(subfd) {}
public:
    inline void close() {
        int err = sqsh_close(subfd);
        if (err != 0) PYSQSH_RAISE(err);
        subfd = NULL;
    }
    inline uint32_t get_xattr_index() {
        PYSQSH_CHECK_CLOSED(subfd);
        return sqsh_file_xattr_index(subfd);
    }
    inline uint32_t get_uid() {
        PYSQSH_CHECK_CLOSED(subfd);
        return sqsh_file_uid(subfd);
    }
    inline uint32_t get_gid() {
        PYSQSH_CHECK_CLOSED(subfd);
        return sqsh_file_gid(subfd);
    }
    inline enum SqshFileType get_type() {
        PYSQSH_CHECK_CLOSED(subfd);
        return sqsh_file_type(subfd);
    }
    inline uint32_t get_hard_link_count() {
        PYSQSH_CHECK_CLOSED(subfd);
        return sqsh_file_hard_link_count(subfd);
    }
    // inline int to_stream(FILE* stream) {
    //     PYSQSH_CHECK_CLOSED(subfd);
    //     int read_bytes = sqsh_file_to_stream(subfd);
    //     if (read_bytes < 0) PYSQSH_RAISE(err);
    //     return read_bytes;
    // }
    // inline int to_stream(nb::object stream) {
    //     PYSQSH_CHECK_CLOSED(subfd);
    //     int fd = PyObject_AsFileDescriptor(stream);
    //     FILE* fp = fdopen(fd, "w");
    //     return to_stream(fp);
    //     // TODO: close fp
    // }
    inline uint32_t get_device_id() {
        PYSQSH_CHECK_CLOSED(subfd);
        return sqsh_file_device_id(subfd);
    }
    inline bool is_extended() {
        PYSQSH_CHECK_CLOSED(subfd);
        return sqsh_file_is_extended(subfd);
    }
    inline uint32_t get_modified_time() {
        PYSQSH_CHECK_CLOSED(subfd);
        return sqsh_file_modified_time(subfd);
    }
    inline uint16_t get_permissions() {
        PYSQSH_CHECK_CLOSED(subfd);
        return sqsh_file_permission(subfd);
    }
    inline uint64_t get_size() {
        PYSQSH_CHECK_CLOSED(subfd);
        return sqsh_file_size(subfd);
    }
};

class PySqshArchive {
    struct SqshArchive* fd;
public:
    PySqshArchive(const std::string path) {
        PYSQSH_CHECK_CLOSED(fd);
        int err;
        fd = sqsh_archive_open(path.data(), NULL, &err);
        if (fd == NULL) PYSQSH_RAISE(err);
    }
    inline void close() {
        PYSQSH_CHECK_CLOSED(fd);
        int err = sqsh_archive_close(fd);
        if (err != 0) PYSQSH_RAISE(err);
    }
    inline PySqshFile open(const std::string path) {
        PYSQSH_CHECK_CLOSED(fd);
        int err;
        struct SqshFile* subfd = sqsh_open(fd, path.data(), &err);
        if (subfd == NULL) PYSQSH_RAISE(err);
        return PySqshFile(subfd);
    }
    inline PySqshFile open(uint64_t inode) {
        PYSQSH_CHECK_CLOSED(fd);
        int err;
        struct SqshFile* subfd = sqsh_open_by_ref(fd, inode, &err);
        if (subfd == NULL) PYSQSH_RAISE(err);
        return PySqshFile(subfd);
    }
};

NB_MODULE(pylibsqsh_ext, m) {
    nb::class_<PySqshArchive>(m, "SqshArchive")
        .def(nb::init<const std::string &>())
        .def("__enter__", [&](PySqshArchive& r) { return r; } )
        .def("__exit__", [&] (PySqshArchive& r, nb::handle exc_type, nb::handle exc_value, nb::handle traceback)
            {
                r.close(); 
            },
            "exc_type"_a.none(),
            "exc_value"_a.none(),
            "traceback"_a.none()
        )
        // .def("open", &PySqshArchive::open)
        .def("open", [&](PySqshArchive& r, const std::string path) { return r.open(path); } )
        .def("open", [&](PySqshArchive& r, uint64_t inode) { return r.open(inode); } )
        .def("close", [&](PySqshArchive& r) { r.close(); } );

    nb::class_<PySqshFile>(m, "SqshFile")
        .def("__enter__", [&](PySqshFile& r) { return r; } )
        .def("__exit__", [&] (PySqshFile& r, nb::handle exc_type, nb::handle exc_value, nb::handle traceback)
            {
                r.close(); 
            },
            "exc_type"_a.none(),
            "exc_value"_a.none(),
            "traceback"_a.none()
        )
        .def("close", [&](PySqshFile& r) { r.close(); } )
        .def_prop_ro("uid", [&](PySqshFile& r) { return r.get_uid(); } )
        .def_prop_ro("gid", [&](PySqshFile& r) { return r.get_gid(); } )
        .def_prop_ro("type", [&](PySqshFile& r) { return r.get_type(); } )
        .def_prop_ro("device_id", [&](PySqshFile& r) { return r.get_device_id(); } )
        .def_prop_ro("is_extended", [&](PySqshFile& r) { return r.is_extended(); } )
        .def_prop_ro("_modified_time", [&](PySqshFile& r) { return r.get_modified_time(); } )
        .def_prop_ro("permissions", [&](PySqshFile& r) { return r.get_permissions(); } )
        .def_prop_ro("size", [&](PySqshFile& r) { return r.get_size(); } )
        .def_prop_ro("hard_link_count", [&](PySqshFile& r) { return r.get_hard_link_count(); } );

    nb::enum_<enum SqshFileType>(m, "SqshFileType")
        .value("UNKNOWN", SQSH_FILE_TYPE_UNKNOWN)
        .value("DIRECTORY", SQSH_FILE_TYPE_DIRECTORY)
        .value("FILE", SQSH_FILE_TYPE_FILE)
        .value("SYMLINK", SQSH_FILE_TYPE_SYMLINK)
        .value("BLOCK", SQSH_FILE_TYPE_BLOCK)
        .value("CHAR", SQSH_FILE_TYPE_CHAR)
        .value("FIFO", SQSH_FILE_TYPE_FIFO)
        .value("SOCKET", SQSH_FILE_TYPE_SOCKET);
}

        // .def("bark", &Dog::bark)
        // .def_rw("name", &Dog::name);
