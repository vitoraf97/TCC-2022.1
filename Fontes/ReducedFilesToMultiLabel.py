# Produzir arquivos reduzidos com labels em binário para uso por classificadores Multi_label
# Nome: ReducedFilesToMultiLabel.py
# Nome do Aluno: Vitor de Avila Falcão
# Matricula: 2019201206
# Curco: Ciência da Computação - Unicarioca - Rio Comprido
# Disciplina: TCC 2022.1
# Data: 18/04/2022
# Orientador: Prof Fabio Henrique Silva
# pré-condições:
# Os arquivos com os dados de cada ataque devem estar no diretório ,/attacks/
# Os arquivos reduzidos devem esta no diretório ./reduzidos/
# Saída:
# o arquivo reduzido será escrito no diretório ./multilabels/

import os
import time
import pandas as pd
import FeaturesImportance as fi

# Função utilizada para gerar o novo diretório ./multilabels/
def folder(f_name):
  try:
    if not os.path.exists(f_name):
      os.makedirs(f_name)
  except OSError:
    print("The folder could not be created!")

if __name__ == "__main__":
  # Get initial Time
  seconds = time.time()

  # Cria lista de nomes de arquivos de ataque a partir do diretório ./attacks
  attack_files = os.listdir("attacks")

  # Cria lista de nomes de arquivos de ataque reduzidos do diretório ./reduzidos
  reduced_files = os.listdir("reduzidos")

  # Obter a lista de ataques
  # removendo .csv para cada arquivo de ataque da lista
  attacks = fi.Get_List_of_Attacks(attack_files)
  print(attacks)

  # Cria o diretório ./multilabels
  folder("./multilabels/")

  # Inicia a tranformação para cada arquivo reduzido
  for arquivo in reduced_files:

    # Criar um dataframe para o arquivo reduzido
    df = pd.read_csv(".//reduzidos//"+arquivo, low_memory=False)
    print(df.head())

    # Acertar colunas dos ataques
    for atq in attacks:
      if atq != "Web Attack":
        df.loc[df['Label'] == atq, atq] = 1
        df.loc[df['Label'] != atq, atq] = 0
      else:
        df.loc[df['Label'] == "Web Attack - Brute Force" , atq] = 1
        df.loc[df['Label'] == "Web Attack - XSS", atq] = 1
        df.loc[df['Label'] == "Web Attack - Sql Injection", atq] = 1
        df.loc[df['Label'] != "Web Attack - Brute Force", atq] = 0
        df.loc[df['Label'] != "Web Attack - XSS", atq] = 0
        df.loc[df['Label'] != "Web Attack - Sql Injection", atq] = 0

    # Acertar a coluna Benign
    df.loc[df['Label'] == "BENIGN", "Benign"] = 1
    df.loc[df['Label'] != "BENIGN", "Benign"] = 0


    print(df.head())

    # Salvar arquivo transformado para multilabel
    df.to_csv(".//multilabels//"+arquivo[0:-4]+".ml.csv", encoding='utf-8')


  print("mission accomplished!")
  print("Total operation time: = ", time.time() - seconds, "seconds")

