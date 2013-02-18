import sys, os
import unittest
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import utils


class UnsafeKnownValues(unittest.TestCase):
    known_values = [('<', '', '&lt;'),
                    ('>', '', '&gt;'),
                    ('&', '', '&amp;'),
                    ('ababa', 'a', 'bb'),
                    ('"', '', '&quot;')]
         

    def test_clean_known_values(self):
        '''clean_input should give known result with known input'''
        for string, opt, output in self.known_values:
            result = utils.clean_input(string, [opt])
            self.assertEqual(output, result)

class HashSanityCheck(unittest.TestCase):
    def setUp(self):
        self.salt = utils.make_salt()

    def test_password_check_sanity(self):
        '''valid_password should correctly verify password digest'''
        result = utils.valid_password('1234', utils.make_hash('1234', self.salt))
        self.assertTrue(result)

    def test_cookie_hash_check_sanity(self):
        '''valid_cookie_hash should correctly verify cookie hash'''
        result = utils.valid_cookie_hash(utils.make_cookie_hash('1234'))
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()

