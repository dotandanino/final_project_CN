# Libraries and imports we used in our project

1. import pyshark
2. import numpy as np
3. import pandas as pd
4. from sklearn.model_selection import train_test_split
5. from sklearn.metrics import accuracy_score
6. from sklearn.neighbors import KNeighborsClassifier
7. from sklearn.preprocessing import StandardScaler
8. import nest_asyncio
9. nest_asyncio.apply()

---

# Instructions for Running the Project
# 1. Graphs
   - running the main.py will give you all the plots we created based on the wireshark records we used
# 2. Attacker with flowID
   - to run the first part of the attacker when he also have access for the 4-tupple flowID you should run the attack.py file and choose the option you want
     1. 1 if you want to check the model accuracy
     2. 2 if you want to run the model with the bonus pcap
     3. 3 if you want to run the model with your own pcap
# 3. Attacker without flowID
   - to run the first part of the attacker when he doesn't have access for the 4-tupple flowID you should run the attacker_part_b.py file and choose the option you want
     1. 1 if you want to check the model accuracy
     2. 2 if you want to run the model with the bonus pcap
     3. 3 if you want to run the model with your own pcap
   - if you choose to upload your own pcap you should upload it as pcapng file and he should be in thw src folder
---
# important links
   - our pcap:
     - https://drive.google.com/drive/folders/1nWHTfKZEwOR8D8HOoybhYWwobE7FwCKb?usp=sharing
   - our github
     - https://github.com/dotandanino/final_project_CN.git