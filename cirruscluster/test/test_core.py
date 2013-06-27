from cirruscluster import core
import unittest

class TestCoreFunctions(unittest.TestCase):

#   def setUp(self):
#     self.seq = range(10)
# 
#   def test_shuffle(self):
#     # make sure the shuffled sequence does not lose any elements
#     random.shuffle(self.seq)
#     self.seq.sort()
#     self.assertEqual(self.seq, range(10))
# 
#     # should raise an exception for an immutable sequence
#     self.assertRaises(TypeError, random.shuffle, (1,2,3))
# 
#   def test_choice(self):
#     element = random.choice(self.seq)
#     self.assertTrue(element in self.seq)
# 
#   def test_sample(self):
#     with self.assertRaises(ValueError):
#       random.sample(self.seq, 20)
#     for element in random.sample(self.seq, 5):
#       self.assertTrue(element in self.seq)

#  Bad test... the ami database changes periodically            
#   def test_SearchUbuntuAmiDatabase(self):
#     release_name = 'precise'
#     region_name = 'us-east-1'
#     root_store_type = 'ebs'
#     virtualization_type = 'paravirtual'
#     selected_ami = core.SearchUbuntuAmiDatabase(release_name, 
#                                                 region_name, 
#                                                 root_store_type,
#                                                 virtualization_type)
#     self.assertEqual(selected_ami, 'ami-e7582d8e')
    
  def test_IsHPCInstanceType(self): 
    self.assertFalse(core.IsHPCInstanceType('c1.xlarge'))
    self.assertTrue(core.IsHPCInstanceType('cc1.4xlarge'))
    self.assertTrue(core.IsHPCInstanceType('cc2.8xlarge'))
    self.assertTrue(core.IsHPCInstanceType('cr1.8xlarge'))
                            

if __name__ == '__main__':
    unittest.main()