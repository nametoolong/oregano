if __name__ == '__main__':
    import unittest

    suite = unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.discover('oregano.tests'))

    unittest.TextTestRunner().run(suite)
