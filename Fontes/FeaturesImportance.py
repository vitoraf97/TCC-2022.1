# Calculo Alternativo de Importancia das Features para Detecção de Anomalias/Ataques em Redes de Computadores
# Nome: FeaturesImportance.py
# Nome do Aluno: Vitor de Avila Falcão
# Matricula: 2019201206
# Curso: Ciência da Computação - Unicarioca - Rio Comprido
# Disciplina: TCC 2022.1
# pré-condições:
# Os arquivos com dados gravados para cada ataque deverão estar no diretório ./attacks
# Os arquivos com as listas de importância processadas para cada ataque deverão estar no diretório ./importances
# Data: 13/04/2022
# Orientador: Prof Fabio Henrique Silva

import os
import pandas as pd
import time
import operator
import warnings

warnings.filterwarnings("ignore")

# Gerar um dicionário de ataques:
# key -  o tipo de ataque e o
# valor - tuples (Contagem de ataques, Contagem de linhas do arquivo)
# entrada:
# attacks - lista de ataques
def Generate_Dictionary_Attacks(attacks):
  attacks_dict = {}
  for atq in attacks:
     # obter o nome do arquivo de ataque
     atq_file = atq + ".csv"
     sample_file = r'.\\attacks\\'+atq_file
     df = pd.read_csv(sample_file, dtype={'Label': 'str'})
     total_count = len(df)
     atq_count = total_count-df["Label"].value_counts().BENIGN
     attacks_dict[atq] = (atq_count, total_count)
  del df
  return attacks_dict

# Calcular uma lista de pesos para cada ataque a partir do dicionário de ataques
# entrada:
# attacks_dict - dicionário de ataques obtido por Generate_Dictionary_Attacks
def Generate_Weights_For_Attacks(attacks_dict):
  lcontrib = [attacks_dict[key][0] for key in attacks_dict]
  total = sum(lcontrib)
  lweights = [x/total for x in lcontrib]
  return lweights

# Gerar um dicionário de importâncias
# sendo a key o tipo de ataque e
# o valor a importância do ataque
# Entradas:
# attacks - lista de ataques
# features - lista de features
# lweights - lista de pesos para cada ataque
def Generate_Dictionary_Importances(attacks, features, lweights):
  print("\n Generate_Dictionary_Importances")
  features_importance_dict = {x: 0.0 for x in features}
  count_attacks = 0
  for atq in attacks:
    atq_imp_file = atq + ".csvimportance.csv"
    sample_file = r'.\\importances\\' + atq_imp_file
    df = pd.read_csv(sample_file)
    for feat in features:
      lindice = df[df["Features"] == str(feat)].index.values
      if len(lindice): # if not empty list
        indice = lindice[0]
        valor = df.iloc[indice][1]
        features_importance_dict[feat] = features_importance_dict[feat]+valor*lweights[count_attacks]
    count_attacks += 1
    del df
  features_importance_dict = dict(sorted(features_importance_dict.items(), key=operator.itemgetter(1), reverse=True))
  return features_importance_dict

# Salvar lista de importâncias alternativa para arquivo
# Entrada:
# features_importance_dict - dicionário de imporâncias das features obtido por Generate_Dictionary Importances
def save_features_importance_to_file(features_importance_dict):
  df = pd.DataFrame(list(features_importance_dict.items()))
  df.to_csv("alt_all_data.csvimportance.csv")
  del df

# Obter lista de ataques a partir dos nomes dos arquivos de ataque
# Entrada:
# attack_files - lista de arquivos e ataque
def Get_List_of_Attacks(attack_files):
  lencsv = len(".csv")
  attacks = [x[0:len(x) - lencsv] for x in attack_files]
  return attacks

# Obter a lista com o nome das Features
# Essa lista está gravado na primeira linha de todos os arquivos de ataque
def Get_Feature_Names():
  shortestattackfile = r'.\\attacks\\Heartbleed.csv';
  df = pd.read_csv(shortestattackfile)
  # Eliminar a coluna 'Label' de df
  del df["Label"]
  feature_names = list(df.columns.values)
  del df
  return feature_names

if __name__ == "__main__":
  # Obter o tempo inicial
  seconds = time.time()

  # Obter a lista de nomes de arquivos de ataque
  attack_files = os.listdir("attacks")  # Cria lista de arquivos de ataque  no diretório ./attacks

  #Obter a lista de ataques
  attacks = Get_List_of_Attacks(attack_files)

  # Obter a lista de arquivos de importância para cada ataque
  importance_files = os.listdir("importances")  # Cria uma lista com os nomes dos arquivos no diretorio ./importances.

  # Extrai a lista de nomes das Features a partir do menor arquivo de ataque
  feature_names = Get_Feature_Names()

  # Gera dicionário de ataques contendo tuplas (contagem do ataque, contagem total do arquivo de ataque)
  # O dicionário será utilizado para ponderar importânicas
  attacks_dict = Generate_Dictionary_Attacks(attacks)
  print("dicionario de ataques")
  print(attacks_dict)

  # Gera a lista de pesos para todos os ataques
  lweights = Generate_Weights_For_Attacks(attacks_dict)
  print("lweights")
  print(lweights)

  # Constroi o dicionário de importâncias a partir da média ponderada
  # das importâncias obtidas pelo processamento de cada arquivo em separado
  features_importance_dict = Generate_Dictionary_Importances(attacks, feature_names, lweights)

  # Salvar a lista de importâncias calculada por média ponderada para um arquivo
  save_features_importance_to_file(features_importance_dict)

  print("mission accomplished!")
  print("Total operation time: = ", time.time() - seconds, "seconds")

