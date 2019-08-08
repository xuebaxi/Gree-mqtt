import unittest
from gree import gController


class ControllerTestCase(unittest.TestCase):

    def test_OnOffSwitch(self):
        c = gController('192.168.31.84')
        _pack = c.gp.packIt(["Pow"], type=0)
        before = c.g.sendcom(_pack)
        c.OnOffSwitch()
        after = c.g.sendcom(_pack)
        self.assertNotEqual(before, after)

if __name__ == '__main__':
    unittest.main()