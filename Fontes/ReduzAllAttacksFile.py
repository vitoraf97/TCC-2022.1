# Redução controlada do arquivo de gravação de dados de ataques
# para um número linhas especificado
# Nome: FeatureImportanceAnalysis.py
# Nome do Aluno: Vitor de Avila Falcão
# Matricula: 2019201206
# Curco: Ciência da Computação - Unicarioca - Rio Comprido
# Disciplina: TCC 2022.1
# Data: 17/04/2022
# Orientador: Prof Fabio Henrique Silva
# pré-condições:
# Os arquivos com os dados de cada ataque deverão estar no diretório ,/attacks/
# Saída:
# o arquivo reduzido será escrito no diretório ./reduzidos/

import os
import time
import FeaturesImportance as fi
import numpy as np


# Função utilizada para gerar o novo diretório ./reduzidos/
def folder(f_name):
  try:
    if not os.path.exists(f_name):
      os.makedirs(f_name)
  except OSError:
    print("The folder could not be created!")

# Calcula lista de pesos para cada ataque a partir dos arquivos do dicionário ./attacks/
# Entrada:
# attacks_dict: dicionário de ataques
# key -  o tipo de ataque e o
# valor - tuples (Contagem de ataques, Contagem de linhas do arquivo)
# Saida:
# Lista de pesos de cada ataque
def Generate_Weights_For_Attacks_Files(attacks_dict):
  lcontrib = [attacks_dict[key][1] for key in attacks_dict]
  total = sum(lcontrib)
  lweights = [x/total for x in lcontrib]
  return lweights

# Gerar dicionário de ataques com contagem reduzida para
# o número de linhas estipulado utilizando
# redução proporcional ao número de linas de ataque
# nos arquivos de gravação de ataques originais
# Preserva a contagem nínima doa ataques HeartBleed
# e Infiltration
# Para tal é feita uma compensação em DoS Hulk
# Entradas:
# attacks: lista de ataques
# numlinhas: Meta de redução do número de linhas
# lweights: lista de pesos de cada ataque
# Saída:
# dicionário de ataques
# key -  o tipo de ataque e o
# valor - tuples (Contagem de ataques, Contagem de linhas do arquivo)
def Generate_Dictionary_Reduced_Attacks(attacks, numlinhas, lweights):
  lweightsarray = np.asarray(lweights)
  # Criterio de seleção de Linhas - FCFS - First Come First Served
  linhasporarquivoataque = numlinhasreduz * lweightsarray
  attacks_red_dict = {}
  Ind = 0
  for atq in attacks:
    attacks_red_dict[atq] = (round(0.30 * (linhasporarquivoataque[Ind])), round(linhasporarquivoataque[Ind]))
    Ind = Ind + 1

  # ajustes para manter os minimos de HeartBleed e Infiltration sem redução
  # Tirar dos maiores, i.e. DoS Hulk e PortScan
  compens2 = 41 - attacks_red_dict["Heartbleed"][1]
  compens1 = 119 - attacks_red_dict["Infiltration"][1]
  attacks_red_dict["Heartbleed"] = (11, 41)
  attacks_red_dict["Infiltration"] = (36, 119)
  compensado1 = attacks_red_dict["DoS Hulk"][1]-compens1
  attacks_red_dict["DoS Hulk"] = (round(0.3*(compensado1)), compensado1)
  compensado2 = attacks_red_dict["PortScan"][1] - compens2
  attacks_red_dict["PortScan"] = (round(0.3 * (compensado2)), compensado2)

  #ajuste final pela soma total, altera o valot total de Dos Hulk
  soma = ObterSomaAttackDict(attacks_red_dict)
  delta = numlinhas-soma
  numataques = attacks_red_dict["DoS Hulk"][0]
  numtotal = attacks_red_dict["DoS Hulk"][1]
  attacks_red_dict["DoS Hulk"] = (numataques, numtotal+delta)

  return attacks_red_dict

# Obtem a contagem total de linhas do dicionário de ataques
# Entrada:
# attacks_dict: dicionário de ataques
# key -  o tipo de ataque e o
# valor - tuples (Contagem de ataques, Contagem de linhas do arquivo)
# Saída:
# Contagem do total de linhas do dicionário de ataque
def ObterSomaAttackDict(attacks_dict):
  lcontrib = [attacks_dict[key][1] for key in attacks_dict]
  soma = sum(lcontrib)
  return soma

# Gerar arquivo único com todos os ataques e contagem reduzida
# Entrada:
# attacks_dict: dicionário de ataques
# key -  o tipo de ataque e o
# valor - tuples (Contagem de ataques, Contagem de linhas do arquivo)
# attacks_red_dict: dicionário de ataques
# key -  o tipo de ataque e o
# valor - tuples (Contagem de ataques, Contagem de linhas do arquivo)
# Saída:
# Arquivo único com todos os ataques e contagem reduzida
# salvo no diretório ./reduzidos/.
def GeneratedReducedFile(attack_files, attacks_red_dict, numlinhasreduz):
  # Loop para  os arquivos de ataques
  strlinhas = str(numlinhasreduz)[0:-3]
  outfile = open(".//reduzidos//reducedallattackfiles"+strlinhas+".csv", "w")
  print("reducedallattackfiles"+strlinhas+".csv"+" is opened")
  conttotallin = 0
  FirstFile = True
  # attack_files = ["Bot.csv"]
  for attackfile in attack_files:
    infile = open(".//attacks//" + attackfile, "r")
    atq = attackfile[0:-4]
    # obter limites de ataques e de benignos
    limatq = attacks_red_dict[atq][0]
    limbenigno = attacks_red_dict[atq][1] - limatq
    countlin = 0
    countatq = 0
    countbenign = 0

    while (True):
      line = infile.readline()

      if (countlin == 0):
        if (FirstFile):
          outfile.write(line)
          FirstFile = False
      else:
        listlinestr = line.split(',')
        #if (conttotallin == 0):
        #print(listlinestr)
        # if atq in listlinestr:
        if atq in listlinestr or \
        ((atq == "Web Attack")
        and (("Web Attack - Brute Force" in listlinestr)
        or ("Web Attack - XSS" in listlinestr)
        or ("Web Attack - Sql Injection" in listlinestr))
        ):
          # escrever linhas de ataques se o contador não suplantou o limite
          if (countatq < limatq):
            outfile.write(line)
            countatq = countatq + 1
            conttotallin = conttotallin+1
        else:
          # escrever linha de benignos se contador não suplantou o limite
          if (countbenign < limbenigno):
            outfile.write(line)
            countbenign = countbenign + 1
            conttotallin = conttotallin+1

      countlin = countlin + 1
      if not line:
        break

    infile.close()
  outfile.close()
  print("reducedallattackfiles"+strlinhas+".csv"+" is closed")
  print("Numero total de Linhas:")
  print(conttotallin)



if __name__ == "__main__":
  # Get initial Time
  seconds = time.time()

  # linhas de 50.000 até 250.000 passo de 50.000
  linhas = list(range(50000, 300000, 50000))
  print("linhas")
  print(linhas)

  # Obter a lista de arquivos de ataque a partir do diretório ./attacks
  attack_files = os.listdir("attacks")

  folder("./reduzidos/")
  # Obter a lista de ataques
  # removendo .csv de cada arquivo de ataque da lista
  attacks = fi.Get_List_of_Attacks(attack_files)

  # Extrair a lista de nomes das Features do menor arquivo de ataque
  feature_names = fi.Get_Feature_Names()

  # Gerar dicionário de ataques com as tuplas (contagem de cada ataque, contagem total do arquivo de ataque)
  attacks_dict = fi.Generate_Dictionary_Attacks(attacks)

  # Gerar pesos a partir do dicionario de ataques
  lweights = Generate_Weights_For_Attacks_Files(attacks_dict)

  for numlinhasreduz in linhas:
    attacks_red_dict = Generate_Dictionary_Reduced_Attacks(attacks, numlinhasreduz, lweights)

    soma = ObterSomaAttackDict(attacks_red_dict)
    print("Confirmando número de linhas do arquivo a ser gerado:")
    print(soma)

    # Gerar arquivo de ataques reduzido
    GeneratedReducedFile(attack_files, attacks_red_dict, numlinhasreduz)

  print("mission accomplished!")
  print("Total operation time: = ", time.time() - seconds, "seconds")







































































































































