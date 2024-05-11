import pandas as pd
import networkx as nx
from Crypto.Util.number import long_to_bytes as l2b

transactions_df = pd.read_csv('transactions_list.csv')
G = nx.DiGraph()
for _, row in transactions_df.iterrows():
    G.add_edge(row['From'], row['To'], weight=row['Amount'])
used_shady_accounts = set()
used_main_accounts = set()
shady_main_pairs = []
total_difference = 0
for node in G.nodes():
    if G.out_degree(node) == 1 and node not in used_shady_accounts:
        tmp = list(G.out_edges(node, data=True))
        outgoing_amount = sum([edge['weight'] for _, _, edge in tmp])
        for _, target_node, edge_data in tmp:
            if target_node not in used_main_accounts:
                incoming_amount = sum([edge['weight'] for _, _, edge in G.in_edges(target_node, data=True)])
                difference = abs(outgoing_amount - incoming_amount)
                shady_main_pairs.append((node, target_node, difference))
                total_difference += difference
                used_shady_accounts.add(node)
                used_main_accounts.add(target_node)

shady_main_pairs_sorted = sorted(shady_main_pairs, key=lambda x: x[2])
print(shady_main_pairs_sorted)
print("Total Difference:", total_difference)

k = (total_difference ** 4) ^ 0x6811D0B1578F512AD3FE8AD453802D87DA82A9DB6BD4A5BF3D81CC
print(l2b(k))