import unittest
from logging import DEBUG
from gree import gController, logger

logger.setLevel(DEBUG)

class ControllerTestCase(unittest.TestCase):

    def test_PowerSwitch(self):
        cmd = "Pow"
        c = gController()
        before = c.checkCurStatus(cmd)
        c.setCmd(cmd.encode())
        after = c.checkCurStatus(cmd)
        self.assertNotEqual(before, after)

    def test_downTem(self):
        c = gController()
        before = c.checkCurStatus("SetTem")
        c.setCmd(b"downTem")
        after = c.checkCurStatus("SetTem")
        self.assertNotEqual(before, after)


if __name__ == '__main__':
    unittest.main()