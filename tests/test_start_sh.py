"""Tests for start.sh: syntax, python discovery (LAGLENS_DRYRUN=1), restart loop."""
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
START = ROOT / "start.sh"
BASH = shutil.which("bash")


def run_sh(args, env=None, cwd=None, timeout=60):
    e = dict(os.environ)
    e.pop("LAGLENS_PYTHON", None)
    e.pop("LAGLENS_DRYRUN", None)
    e.update(env or {})
    return subprocess.run([BASH, str(START)] + list(args), capture_output=True, text=True, env=e, cwd=cwd or str(ROOT), timeout=timeout)


@unittest.skipIf(BASH is None, "bash not available")
class StartShTests(unittest.TestCase):
    def test_syntax(self):
        cp = subprocess.run([BASH, "-n", str(START)], capture_output=True, text=True)
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_dryrun_prefers_laglens_python(self):
        cp = run_sh([], env={"LAGLENS_DRYRUN": "1", "LAGLENS_PYTHON": sys.executable})
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout.strip(), sys.executable)

    def test_dryrun_finds_some_python_39(self):
        cp = run_sh([], env={"LAGLENS_DRYRUN": "1"})
        self.assertEqual(cp.returncode, 0, cp.stderr)
        chosen = cp.stdout.strip()
        self.assertTrue(os.access(chosen, os.X_OK), chosen)
        check = subprocess.run([chosen, "-c", "import sys; print(sys.version_info >= (3, 9))"], capture_output=True, text=True)
        self.assertEqual(check.stdout.strip(), "True")

    def test_dryrun_rejects_old_python(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-sh-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        fake = tmp / "oldpython"
        fake.write_text("#!/bin/sh\nexit 1\n")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        cp = run_sh([], env={"LAGLENS_DRYRUN": "1", "LAGLENS_PYTHON": str(fake)})
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertNotEqual(cp.stdout.strip(), str(fake))

    def test_no_python_message(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-sh-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        # copy start.sh into a sandbox and neuter every candidate via an empty PATH and a bad LAGLENS_PYTHON
        sandbox = tmp / "lag-lens"
        sandbox.mkdir()
        shutil.copy(START, sandbox / "start.sh")
        script = (sandbox / "start.sh").read_text().replace(
            "candidates+=(/opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3)",
            "candidates+=(/nonexistent/python3)",
        )
        (sandbox / "start.sh").write_text(script)
        cp = subprocess.run([BASH, str(sandbox / "start.sh"), "--version"], capture_output=True, text=True,
                            env={"PATH": "/nonexistent", "LAGLENS_PYTHON": "/nonexistent/py"}, cwd=str(sandbox))
        self.assertEqual(cp.returncode, 1)
        self.assertIn("Python 3.9", cp.stderr)

    def test_version_through_start_sh(self):
        cp = run_sh(["--version"], env={"LAGLENS_PYTHON": sys.executable})
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout.strip(), (ROOT / "VERSION").read_text().strip())

    def test_restart_loop_adds_resume(self):
        """A fake run.py exits 1 once; start.sh must retry with --resume sessions/<last>."""
        tmp = Path(tempfile.mkdtemp(prefix="laglens-sh-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        sandbox = tmp / "lag-lens"
        sandbox.mkdir()
        shutil.copy(START, sandbox / "start.sh")
        (sandbox / "sessions" / "20261011-190000").mkdir(parents=True)
        (sandbox / "sessions" / ".last").write_text("sessions/20261011-190000\n")
        (sandbox / "run.py").write_text(
            "import os, sys\n"
            "log = open('calls.txt', 'a'); log.write(' '.join(sys.argv[1:]) + '\\n'); log.close()\n"
            "n = sum(1 for _ in open('calls.txt'))\n"
            "sys.exit(1 if n == 1 else 0)\n"
        )
        cp = subprocess.run([BASH, str(sandbox / "start.sh"), "--no-browser"], capture_output=True, text=True,
                            env=dict(os.environ, LAGLENS_PYTHON=sys.executable), cwd=str(sandbox), timeout=60)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        calls = (sandbox / "calls.txt").read_text().splitlines()
        self.assertEqual(calls, ["--no-browser", "--no-browser --resume sessions/20261011-190000"])
        self.assertIn("restarting in 3 s (1/20", cp.stderr)

    def test_resume_is_a_run_command_and_loops(self):
        """`start.sh --resume sessions/<id>` is a monitor run: a crash is restarted."""
        tmp = Path(tempfile.mkdtemp(prefix="laglens-sh-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        sandbox = tmp / "lag-lens"
        sandbox.mkdir()
        shutil.copy(START, sandbox / "start.sh")
        (sandbox / "sessions" / "20261011-190000").mkdir(parents=True)
        (sandbox / "sessions" / ".last").write_text("sessions/20261011-190000\n")
        (sandbox / "run.py").write_text(
            "import sys\n"
            "log = open('calls.txt', 'a'); log.write(' '.join(sys.argv[1:]) + '\\n'); log.close()\n"
            "n = sum(1 for _ in open('calls.txt'))\n"
            "sys.exit(1 if n == 1 else 0)\n"
        )
        cp = subprocess.run([BASH, str(sandbox / "start.sh"), "--resume", "sessions/20261011-190000"], capture_output=True,
                            text=True, env=dict(os.environ, LAGLENS_PYTHON=sys.executable), cwd=str(sandbox), timeout=60)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        calls = (sandbox / "calls.txt").read_text().splitlines()
        self.assertEqual(calls, ["--resume sessions/20261011-190000",
                                 "--resume sessions/20261011-190000 --resume sessions/20261011-190000"])
        self.assertIn("restarting in 3 s (1/20", cp.stderr)

    def _slow_child_sandbox(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-sh-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        sandbox = tmp / "lag-lens"
        sandbox.mkdir()
        shutil.copy(START, sandbox / "start.sh")
        # a run.py whose shutdown takes ~1.5 s after SIGINT/SIGTERM and then writes done.txt
        (sandbox / "run.py").write_text(
            "import signal, sys, time\n"
            "stop = {'v': False}\n"
            "def h(s, f): stop['v'] = True\n"
            "signal.signal(signal.SIGINT, h); signal.signal(signal.SIGTERM, h)\n"
            "open('started.txt', 'w').close()\n"
            "while not stop['v']: time.sleep(0.05)\n"
            "time.sleep(1.5)\n"
            "open('done.txt', 'w').close()\n"
            "sys.exit(0)\n"
        )
        return sandbox

    def _run_and_signal(self, sandbox, send):
        proc = subprocess.Popen([BASH, str(sandbox / "start.sh"), "--no-browser"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=dict(os.environ, LAGLENS_PYTHON=sys.executable), cwd=str(sandbox),
                                start_new_session=True)
        try:
            deadline = time.monotonic() + 20
            while not (sandbox / "started.txt").exists():
                self.assertIsNone(proc.poll(), proc.stderr.read() if proc.poll() is not None else "")
                self.assertLess(time.monotonic(), deadline, "child did not start")
                time.sleep(0.05)
            t_sig = time.monotonic()
            send(proc)
            out, err = proc.communicate(timeout=30)
            elapsed = time.monotonic() - t_sig
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(proc.returncode, 0, err)
        self.assertTrue((sandbox / "done.txt").exists(), "start.sh returned before the child finished shutting down")
        self.assertGreaterEqual(elapsed, 1.4, elapsed)
        self.assertNotIn("restarting", err)

    def test_start_sh_waits_for_child_shutdown_on_sigterm(self):
        sandbox = self._slow_child_sandbox()
        self._run_and_signal(sandbox, lambda p: p.send_signal(signal.SIGTERM))

    def test_start_sh_waits_for_child_shutdown_on_ctrl_c(self):
        sandbox = self._slow_child_sandbox()
        # Ctrl-C = SIGINT to the whole foreground process group (bash and the child)
        self._run_and_signal(sandbox, lambda p: os.killpg(os.getpgid(p.pid), signal.SIGINT))

    def test_one_shot_commands_do_not_loop(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-sh-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        sandbox = tmp / "lag-lens"
        sandbox.mkdir()
        shutil.copy(START, sandbox / "start.sh")
        (sandbox / "run.py").write_text("import sys; sys.exit(3)\n")
        cp = subprocess.run([BASH, str(sandbox / "start.sh"), "--doctor"], capture_output=True, text=True,
                            env=dict(os.environ, LAGLENS_PYTHON=sys.executable), cwd=str(sandbox), timeout=30)
        self.assertEqual(cp.returncode, 3)
        self.assertNotIn("restarting", cp.stderr)


if __name__ == "__main__":
    unittest.main()


class AlreadyRunningExitTests(unittest.TestCase):
    def test_exit_code_3_is_not_restarted(self):
        """run.py exits 3 when another monitor owns the folder: start.sh must pass it through, not loop."""
        tmp = Path(tempfile.mkdtemp(prefix="laglens-sh-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        sandbox = tmp / "lag-lens"
        sandbox.mkdir()
        shutil.copy(START, sandbox / "start.sh")
        (sandbox / "run.py").write_text(
            "import sys\n"
            "open('calls.txt', 'a').write('x\\n')\n"
            "sys.exit(3)\n"
        )
        cp = subprocess.run([BASH, str(sandbox / "start.sh"), "--no-browser"], capture_output=True, text=True,
                            env=dict(os.environ, LAGLENS_PYTHON=sys.executable), cwd=str(sandbox), timeout=60)
        self.assertEqual(cp.returncode, 3, cp.stderr)
        self.assertEqual((sandbox / "calls.txt").read_text().splitlines(), ["x"])
        self.assertNotIn("restarting", cp.stderr)
