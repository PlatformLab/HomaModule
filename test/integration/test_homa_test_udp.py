# Compile and test the UDP client and server with mocked socket I/O,
# checking request counts, errors, and startup transport labels without traffic.

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


MOCK_SOURCE = r"""
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

static int requests = 0;
static int responses = 0;
static size_t message_length = 0;

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
    return dup(STDERR_FILENO);
}

extern "C" int __wrap_setsockopt(int descriptor, int level, int option,
        const void *value, socklen_t value_length)
{
    return 0;
}

extern "C" int __wrap_bind(int descriptor, const struct sockaddr *address,
        socklen_t address_length)
{
    return 0;
}

extern "C" int __wrap_getsockopt(int descriptor, int level, int option,
        void *value, socklen_t *value_length)
{
    const char *protocol = getenv("HOMA_TEST_MOCK_PROTOCOL");
    if (!protocol || strcmp(protocol, "fail") == 0) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (level != SOL_SOCKET || option != SO_PROTOCOL ||
            *value_length != sizeof(int)) {
        errno = EINVAL;
        return -1;
    }
    *static_cast<int *>(value) = atoi(protocol);
    *value_length = sizeof(int);
    return 0;
}

extern "C" ssize_t __wrap_sendmsg(int descriptor,
        const struct msghdr *message, int flags)
{
    requests++;
    message_length = message->msg_iov[0].iov_len;
    const char *failure = getenv("HOMA_TEST_MOCK_FAIL");
    if (failure && strcmp(failure, "send") == 0) {
        errno = EIO;
        return -1;
    }
    return message_length;
}

extern "C" ssize_t __wrap_recvmsg(int descriptor,
        struct msghdr *message, int flags)
{
    responses++;
    if (getenv("HOMA_TEST_MOCK_SERVER"))
        exit(0);
    const char *failure = getenv("HOMA_TEST_MOCK_FAIL");
    if (failure && strcmp(failure, "receive") == 0) {
        errno = EIO;
        return -1;
    }
    return message_length;
}

__attribute__((destructor)) static void report_counts()
{
    fprintf(stderr, "MOCK requests=%d responses=%d length=%zu\n",
            requests, responses, message_length);
}

#ifdef main
#undef main
extern void homa_server(int port);
int main()
{
    homa_server(8000);
    return 0;
}
#endif
"""


class HomaTestUdpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        cls.workspace = tempfile.TemporaryDirectory(
            prefix="homa-test-udp-", dir=root / "test/integration/artifacts")
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.client = Path(cls.workspace.name) / "homa_test"
        cls.server = Path(cls.workspace.name) / "server"
        for program in ("homa_test", "server"):
            definitions = ["-Dmain=homa_server_main"] if program == "server" else []
            subprocess.run([
                "g++", "-std=c++17", "-O2", "-I" + str(root),
                *definitions,
                str(root / "util" / (program + ".cc")),
                str(root / "util/test_utils.cc"),
                str(root / "util/dist.cc"),
                str(root / "util/time_trace.cc"),
                str(root / "homa_receiver.cc"), "-x", "c++", "-",
                "-Wl,--wrap=socket,--wrap=setsockopt,--wrap=sendmsg,--wrap=recvmsg",
                "-Wl,--wrap=bind,--wrap=getsockopt",
                "-lpthread", "-o", str(Path(cls.workspace.name) / program),
            ], input=MOCK_SOURCE, text=True, check=True, capture_output=True)

    def run_client(self, *arguments, failure=None):
        environment = os.environ.copy()
        environment.pop("HOMA_TEST_MOCK_FAIL", None)
        environment.pop("HOMA_TEST_MOCK_SERVER", None)
        if failure:
            environment["HOMA_TEST_MOCK_FAIL"] = failure
        return subprocess.run(
            [str(self.client), "127.0.0.1:8000", *arguments],
            env=environment, text=True, capture_output=True, timeout=10)

    def run_server(self, protocol):
        environment = os.environ.copy()
        environment["HOMA_TEST_MOCK_SERVER"] = "1"
        environment["HOMA_TEST_MOCK_PROTOCOL"] = protocol
        return subprocess.run(
            [str(self.server), "--port", "8000"], env=environment,
            text=True, capture_output=True, timeout=10)

    def test_server_reports_udp_without_verbose(self):
        result = self.run_server("17")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Server transport: Homa-over-UDP (port 8000)", result.stdout)
        self.assertNotIn("Server transport: native Homa", result.stdout)

    def test_server_reports_homa_over_tcp_without_verbose(self):
        result = self.run_server("6")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Server transport: Homa-over-TCP (port 8000)", result.stdout)
        self.assertNotIn("Server transport: unknown", result.stdout)

    def test_server_reports_native_homa_without_verbose(self):
        result = self.run_server("146")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Server transport: native Homa (port 8000)", result.stdout)
        self.assertNotIn("Server transport: Homa-over-UDP", result.stdout)

    def test_server_query_failure_does_not_guess_or_stop(self):
        result = self.run_server("fail")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Server transport: unknown (SO_PROTOCOL failed:", result.stdout)
        self.assertIn("requests=0 responses=1", result.stderr)
        self.assertNotIn("Server transport: native Homa", result.stdout)
        self.assertNotIn("Server transport: Homa-over-UDP", result.stdout)

    def test_server_reports_unrecognized_protocol(self):
        result = self.run_server("253")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Server transport: unknown (IP protocol 253, port 8000)",
                      result.stdout)

    def test_count_and_length_include_ten_warmups(self):
        result = self.run_client(
            "--count", "2", "--length", "1000", "--seed", "1", "udp")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("requests=12 responses=12 length=1000", result.stderr)
        self.assertIn("Bandwidth at median", result.stdout)

    def test_default_count_is_one_thousand(self):
        result = self.run_client("--length", "1000", "udp")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("requests=1010 responses=1010 length=1000", result.stderr)

    def test_rtt_keeps_its_request_count(self):
        result = self.run_client("--count", "2", "rtt")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("requests=12 responses=12", result.stderr)

    def test_udp_send_failure_exits_nonzero(self):
        result = self.run_client("--count", "2", "udp", failure="send")
        self.assertEqual(1, result.returncode)
        self.assertIn("Error in sendmsg", result.stdout)
        self.assertIn("requests=1 responses=0", result.stderr)
        self.assertNotIn("Bandwidth at median", result.stdout)

    def test_udp_receive_failure_exits_nonzero(self):
        result = self.run_client("--count", "2", "udp", failure="receive")
        self.assertEqual(1, result.returncode)
        self.assertIn("Error in recvmsg", result.stdout)
        self.assertIn("requests=1 responses=1", result.stderr)
        self.assertNotIn("Bandwidth at median", result.stdout)

    def test_invoke_operation_is_removed(self):
        result = self.run_client("invoke")
        self.assertEqual(1, result.returncode)
        self.assertIn("Unknown operation 'invoke'", result.stdout)
        self.assertIn("requests=0 responses=0", result.stderr)


if __name__ == "__main__":
    unittest.main()