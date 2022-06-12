# Análise da Importancia das Features para Detecção de Anomalias/Ataques em Redes de Computadores
# Nome: FeatureImportanceAnalysis.py
# Nome do Aluno: Vitor de Avila Falcão
# Matricula: 2019201206
# Curco: Ciência da Computação - Unicarioca - Rio Comprido
# Disciplina: TCC 2022.1
# Data: 13/04/2022
# Orientador: Prof Fabio Henrique Silva
# pré-condições:
# Os arquivos com as listas de importâncias devem estar no diretório ./
# arquivo all_data.csvimportance.csv - Lista de importâncias para o processamento de um único arquivo com todos os ataques
# arquivo alt_all_data.csvimortance.csv - Lista de importâncias para o processamento de arquivos separados para cada ataque

import pandas as pd
import time
import FeaturesImportance as fi
import matplotlib.pyplot as plt

# Obter lista de DataFrames para cada uma das Listas de Importâncias
# em um total de 2 listas de importância
# Entrada:
# Lista de Arquivos de Importância
def Get_Importance_DataFrames(all_importance_files):
  df = [None, None]
  for ind in range(len(all_importance_files)):
    sample_file = r'.\\' + all_importance_files[ind]
    df[ind] = pd.read_csv(sample_file)
    if (ind == 1):
      del df[1]['Unnamed: 0']
    print(df[ind].head())

  return df

# Gerar dicionário de importâncias a partir do Data Frame de Importâncias
# Entrada:
# Data-Frame de importâncias
def Generate_Importance_Dictionary_from_DataFrame(importancedf):
  importance_dict = {importancedf.iloc[ind][0]: importancedf.iloc[ind][1] for ind in importancedf.index}
  return importance_dict

# Gerar listas separadas de Features e Importâncias a partir do dicionário de importâncias
# Entrada:
# Dicionário de Importâncias
def Generate_Separated_Lists_from_Importancedictionary(importance_dict):
  lfeatures = list(importance_dict.keys())
  limportances = list(importance_dict.values())
  return lfeatures, limportances

# Obter percentual de coincidência entre as duas listas de importância
# Entradas:
# lf - Lista de importâncias para arquivo único com todos os ataques
# altlf - lista de importâncias para arquivos separados para cada ataque
def GetPercentOfFeaturesMatches(lf, altlf):
  lenlf = len(lf)
  lenaltlf = len(altlf)
  assert(lenlf==lenaltlf), "Lista Must Hame The Same Size"
  count = 0
  for x in lf:
    for y in altlf:
      if (x == y):
        count = count+1
  return (count/ lenlf)*100.0

# Obter lista de aderencia variando com o número de features selecionadas
# Entradas:
# lf - Lista de importâncias para arquivo único com todos os ataques
# altlf - lista de importâncias para arquivos separados para cada ataque
# numfeatures - número de features a considerar
def Compute_Adherence(lfeatures, altlfeatures, numfeatures):
  lenfeatures = len(lfeatures)
  lenaltfeatures = len(altlfeatures)
  lenmin = min(lenfeatures, lenaltfeatures)
  assert(numfeatures <= lenmin), 'Excessive Numer of features'
  percadher = []
  for ind in range(numfeatures):
    lf = lfeatures[0:ind+1]
    altlf = altlfeatures[0:ind+1]
    perc = GetPercentOfFeaturesMatches(lf, altlf)
    percadher.append(perc)
  return percadher

# Obter Importancia acumuladda por numero de features utilizado
# Calculo para solução com um unico arquivo de ataques dicimp[0]
# e com varios arquivos de ataque separados dictimp[1]
#Entradas:
# dictimp - Lista de dicionários de importância
# numfeatures - número de features a considerar
def GetAccImportance(dictimp, numfeatures):
  lfeatures, limportances = Generate_Separated_Lists_from_Importancedictionary(dictimp[0])
  altlfeatures, altlimportances = Generate_Separated_Lists_from_Importancedictionary(dictimp[1])
  lenfeatures = len(lfeatures)
  lenaltfeatures = len(altlfeatures)
  lenmin = min(lenfeatures, lenaltfeatures)
  assert (numfeatures <= lenmin), 'Excessive Number of features'

  # calculate acc list of importance for all attackks file solution
  lacc = []
  acc = 0.0
  for x in limportances[0:numfeatures]:
    acc = acc + x
    lacc.append(acc*100.0)

  laltacc = []
  altcacc = 0.0
  for ind in range(numfeatures):
    y = dictimp[0][altlfeatures[ind]]
    altcacc = altcacc + y
    laltacc.append(altcacc*100.0)

  # calculate acc list of importance for separated files attacks solution
  return lacc, laltacc

# Plotar Gráfico de Barras
# Entrada:
# lista - lista de valores a plotar
def Plotar_Barras(lista, title = "Grafico de Barras", xlabel = "x", ylabel = "y", hline = 0):
  inds = range(len(lista))
  vals = lista
  labels = [str(ind + 1) for ind in inds]
  fig, ax = plt.subplots()
  rects = ax.bar(inds, vals)
  ax.set_xticks([int(ind) for ind in inds])
  ax.set_xticklabels(labels)
  ax.set_xlabel(xlabel)
  ax.set_ylabel(ylabel)
  ax.set_title(title)
  if (hline != 0):
    ax.axhline(y=hline, color='r')
  plt.show()

if __name__ == "__main__":
  # Get initial Time
  seconds = time.time()

  all_importance_files = ["all_data.csvimportance.csv", "alt_all_data.csvimportance.csv"]
  feature_names = fi.Get_Feature_Names()
  df = Get_Importance_DataFrames(all_importance_files)

  dictimp = [Generate_Importance_Dictionary_from_DataFrame(x) for x in df]

  lfeatures, limportances = Generate_Separated_Lists_from_Importancedictionary(dictimp[0])
  print(lfeatures)
  print(limportances)

  altlfeatures, altlimportances = Generate_Separated_Lists_from_Importancedictionary(dictimp[1])
  print(altlfeatures)
  print(altlimportances)

  numfeatures = 20
  percadher = Compute_Adherence(lfeatures, altlfeatures, numfeatures)
  print(percadher)

  # Plotar aderencia de soluções
  Plotar_Barras(percadher, title="Grau de Aderência da Alternativa Mais Rápida", xlabel="Number of Features", ylabel="Adherence Level(%)", hline=65)

  lacc, laltacc = GetAccImportance(dictimp, numfeatures)
  print(lacc)
  print(len(lacc))
  Plotar_Barras(lacc, title="Importancia Acumulada Arquivo ùnico", xlabel="Number of Features", ylabel="Importancia (%)", hline=lacc[-1])

  print(laltacc)
  print(len(laltacc))
  Plotar_Barras(laltacc, title="Importancia Acumulada Múltiplos Arquivos", xlabel="Number of Features", ylabel="Importancia (%)", hline=laltacc[-1])

  print("mission accomplished!")
  print("Total operation time: = ", time.time() - seconds, "seconds")
















