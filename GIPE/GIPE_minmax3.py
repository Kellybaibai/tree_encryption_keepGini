'''
Descripttion: The Gini-impurity preserving encryption method(get each node's cipher t.cipher by the corresponding ciphertext domain [t_min, t_max]: t.cipher = (t_min+t_max)/2)
version: v2
Author: anonymous
'''

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import time
import random
import os
from joblib import Parallel, delayed

random.seed(42)
# C_MAX=np.finfo(np.float32).max
C_MAX=1e10

class TreeNode:
    '''Definition of Binary Search Tree Node'''    
    def __init__(self,
                 val,
                 label,
                 flag=True,
                 encryptMin=0,
                 encryptMax=C_MAX):
        """
        Parameters
        ----------
        val : list 
            Store plaintexts in the current node.
        left : TreeNode
            The left child node.
        right : TreeNode
            The right child node.
        label : int 
            Record the label in the current node(available when flag is true).
        min : float
            The minimum value of the child nodes of the current node.
        max : float
            The maximum value of the child nodes of the current node.
        flag : boolean
            Judge whether the current node type, True: the node can store different value with consistent lable, False: the node can store consistent value with different labels.
        encryptMin : float
            The ciphertext domain of the current node.
        encryptMax : float
            The ciphertext domain of the current node.
        cipher : float
            The ciphertext of the current node.
        """
        self.val = val   
        self.left = None   
        self.right = None
        self.label = label   
        self.min = float("inf")
        self.max = float("-inf")
        self.flag = flag 
        self.encryptMin = encryptMin
        self.encryptMax = encryptMax
        self.cipher_tab={}


    def get_cipher(self, value):
        '''Get the ciphertext of the plaintext value'''

        if value in self.cipher_tab:
            return self.cipher_tab[value]
        else:
            c=random.uniform(self.encryptMin, self.encryptMax)
            self.cipher_tab[value] = c
            return c

class OperationTree:
    '''Insert plaintext to recursively build encrypted binary search tree'''
    def insert(self,
               root,
               val,
               label):  # encode用来记录此节点在树中的path 左0右1  
        
        """
        Parameters
        ----------
        root : TreeNode
            The node of the binary search tree.
        val : float
            The value of the insert plaintext.
        label : int 
            The label of the insert plaintext.
        encryptMin : float
            The ciphertext domain of the current node.
        encryptMax : float 
            The ciphertext domain of the current node.
        """
        if root == None:
            print('root is None'+str(val))
            root = TreeNode([val], label)  
            root.min = val
            root.max = val

        else:
            # Based on the plaintext's value and label to determine its position node in the binary search tree.
            if (root.flag == True):  
                if (label == root.label):  # do not split the current node
                    if (val <= max(root.val) and val >= min(root.val)):  #Insert this plaintext in this node
                        root.val.append(val)
                    elif (val < min(root.val)):  
                        if val < root.min:
                            root.min = val
                        if (root.left and val <= root.left.max):  #recursively find its left child
                            root.left = self.insert(root.left,
                                                    val,
                                                    label,
                                                    )
                        else:  #Insert this plaintext in this node
                            root.val.append(val)

                    elif (val > max(root.val)):  #Similarly for the right child
                        if val > root.max:
                            root.max = val
                        if (root.right and val >= root.right.min):   
                            root.right = self.insert(root.right,
                                                     val,
                                                     label,
                                                     )
                        else:   
                            root.val.append(val)

                else:  #label != root.label
                    if (val < min(root.val)):   
                        if val < root.min:
                            root.min = val
                        if root.left:
                            root.left = self.insert(root.left,
                                                    val,
                                                    label,
                                                    )
                        else:
                            c=random.uniform(root.encryptMin, root.encryptMax)

                            root.left = TreeNode([val],
                                                label,
                                                encryptMax=c,
                                                encryptMin=root.encryptMin)
                            root.left.min = val
                            root.left.max = val

                            root.encryptMin = c
                            
                    elif (val > max(root.val)):   
                        if val > root.max:
                            root.max = val
                        if root.right:
                            root.right = self.insert(root.right,
                                                    val,
                                                    label,
                                                    )
                        else:
                            c=random.uniform(root.encryptMin, root.encryptMax)
                            
                            root.right = TreeNode([val],
                                                label,
                                                encryptMax=root.encryptMax,
                                                encryptMin=c)
                            root.right.min = val
                            root.right.max = val

                            root.encryptMax = c

                    else:  #Split the current node
                        c1=random.uniform(root.encryptMin, root.encryptMax)
                        c2=random.uniform(root.encryptMin, root.encryptMax)
                        if c1>c2:
                            c1,c2=c2,c1

                        rootLeft = root.left
                        rootright = root.right
                        leftVal = [item for item in root.val if item < val]
                        rightVal = [item for item in root.val if item > val]
                        rootmin = root.min
                        rootmax = root.max
                        if (leftVal): #The split left child
                            left = TreeNode(leftVal,
                                            root.label,
                                            encryptMax=c1,
                                            encryptMin=root.encryptMin)
                            left.min = root.min
                            left.max = max(leftVal)
                        if (rightVal):#The split right child
                            right = TreeNode(rightVal,
                                                root.label,
                                                encryptMin=c2,
                                                encryptMax=root.encryptMax)
                            right.min = min(rightVal)
                            right.max = root.max
                        if (val in root.val):# Update the current node's value
                            rootValue = [
                                item for item in root.val if item == val
                            ]
                            rootValue.append(val)
                            root.val = rootValue
                            root.flag = False
                        else:
                            root.val = [val]
                        root.min = rootmin
                        root.max = rootmax
                        if (leftVal): # Update the current node's child
                            root.left = left
                            root.left.left = rootLeft
                            root.encryptMin = c1
                        else:
                            root.left = rootLeft
                        if (rightVal):
                            root.right = right
                            root.right.right = rootright
                            root.encryptMax = c2
                        else:
                            root.right = rootright

            else:  #root.flag == False
                if (val == root.val[0]):
                    root.val.append(val)

                elif (val < root.val[0]):
                    if val < root.min:
                        root.min = val

                    if root.left:
                        root.left = self.insert(root.left,
                                                val,
                                                label,
                                                )
                    else:
                        c=random.uniform(root.encryptMin, root.encryptMax)

                        root.left = TreeNode([val],
                                            label,
                                            encryptMax=c,
                                            encryptMin=root.encryptMin)
                        root.left.min = val
                        root.left.max = val

                        root.encryptMin = c

                else:
                    if val > root.max:
                        root.max = val

                    if root.right:
                        root.right = self.insert(root.right,
                                                val,
                                                label,
                                                )
                    else:
                        c=random.uniform(root.encryptMin, root.encryptMax)
                        
                        root.right = TreeNode([val],
                                            label,
                                            encryptMax=root.encryptMax,
                                            encryptMin=c)
                        root.right.min = val
                        root.right.max = val

                        root.encryptMax = c
        return root


def inorderTraversal(root):
    '''
    Inorder traversal the built binary search tree.
    '''
    res = []
    def inorder(root):
        if not root:
            return
        res.append([root.val, root.flag])  #root.encryptMin, root.encryptMax
        inorder(root.left)
        inorder(root.right)

    inorder(root)
    # print('val', res)
    return res


def Encode(root, value): 
    '''
    Find the plaintext's corresponding node position in the built binary search tree and return its ciphertext.
    '''
    if (value in root.val):
        return root.get_cipher(value)
    if (value > max(root.val)):
        return Encode(root.right, value)
    if (value < min(root.val)):
        return Encode(root.left, value)


def getCipher(root, values):
    '''
    Find the plaintext's corresponding ciphertext.
    '''
    Cipher = []
    for i in range(len(values)):
        tmpCode = Encode(root, values[i])
        if (not tmpCode): print("error")
        Cipher.append(tmpCode)
    return Cipher


if __name__ == "__main__":
    #Batch encrypt the data
    files = os.listdir("../ExpData/")
    print('files:', files)
    for file in files[1:]:
        dataname = file
        print(dataname)
        start = time.time()
        data_path = '../ExpData/' + dataname
        trainingData = pd.read_csv(data_path, encoding='utf-8-sig')
        
        X_train = trainingData.iloc[:, :-1].values
        Y_train = trainingData.iloc[:, -1].values
        
        # Build a binary tree for each attribute
        train_root = [] 
        Cipher = []

        def process(col):
            Colcipher = []
            op = OperationTree()
            root = TreeNode([X_train[0][col]], Y_train[0])
            for row in range(1, len(X_train)):
                op.insert(root, X_train[row][col], Y_train[row])
            # Get ciphertexts
            Colcipher = getCipher(root, [item[col] for item in X_train])
            return Colcipher

        Cipher = Parallel(n_jobs = min(len(X_train[0]),60), verbose = 1)(delayed(process)(col) for col in range(len(X_train[0])))

        Cipher = pd.DataFrame(Cipher)
        Cipher = pd.DataFrame(Cipher.values.T)   
        Cipher.insert(Cipher.shape[1], 'label', Y_train)   
        # print(Cipher)
        Cipher.to_csv('./OPEminmax_cipher3/' + dataname, index=0)
        X_train = pd.concat([pd.DataFrame(X_train),
                             pd.DataFrame(Y_train)],
                            axis=1)
        pd.DataFrame(X_train).to_csv('./OPEminmax_cipher3/origin_' + dataname,
                                     index=0)
        end = time.time()
        print("time is ", end - start)
