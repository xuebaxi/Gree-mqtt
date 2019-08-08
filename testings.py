import unittest
from gree import gController


class ControllerTestCase(unittest.TestCase):

    def test_OnOffSwitch(self):
        c = gController('192.168.31.84')
        before = c.checkCurStatus("Pow")
        c.OnOffSwitch()
        after = c.checkCurStatus("Pow")
        self.assertNotEqual(before, after)

    def test_setTem(self):
        c = gController('192.168.31.84')
        before = c.checkCurStatus("SetTem")
        c.setTem(before+1)
        after = c.checkCurStatus("SetTem")
        self.assertNotEqual(before, after)


if __name__ == '__main__':
    unittest.main()