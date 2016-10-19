import numpy as np

"""
Analyzes a file called dataMatrix.npz located in the same directory as the file. The first row of the data matrix is assumed to be the feature name. The output is stored in a file called matrixStatistics.txt.
"""

dataMatrix = np.load("dataMatrix.npz")
outputStats = open("matrixStatistics.txt", "w")
data = dataMatrix["arr_0"]
numFeatures = data.shape[1]
numSamples = data.shape[0]
for i in range(numFeatures):
  col = data[:,i]
  feature_name = str(col[0]).strip(" ")
  col = col[1:].astype(np.float)
  import pdb; pdb.set_trace()
  outputStats.write("{}: mean = {}, standard deviation = {}, max = {}, min = {}\n".format(feature_name, col.mean(), col.std(), col.max(), col.min()))

outputStats.close()
