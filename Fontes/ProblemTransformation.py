# Processamento dee Inteligência Artificial Multi-Label para detecção de Ataques
# através da técnica de transformação do problema
# Nome: ProblemTransformation.py
# Nome do Aluno: Vitor de Avila Falcão
# Matricula: 2019201206
# Curco: Ciência da Computação - Unicarioca - Rio Comprido
# Disciplina: TCC 2022.1
# Data: 13/04/2022
# Orientador: Prof Fabio Henrique Silva
# pré-condições:
# Os arquivos com ataques separados devem estar no diretório ./attacks
# O arquivo com as lista de importâncias devem estar no diretório ./
# arquivo all_data.csvimportance.csv - Lista de importâncias para o processamento de um único arquivo com todos os ataques
# Os arquivos de ataques reduzidos preparados para o processamento Multi-Label devem ser colocardos no Diretório ./multilabels
# ex: reducedallattackfiles100.ml.csv


import os
import time
import pandas as pd
import FeaturesImportance as fi
import json

from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score,hamming_loss
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

# Import Transformation Problem Alternatives
from skmultilearn.problem_transform import BinaryRelevance
from skmultilearn.problem_transform import ClassifierChain
from skmultilearn.problem_transform import LabelPowerset

# Testar o modelo de classificação com um método de transformação
# do problema de classificação multi-label para classificação binária
# Entradas:
# model - classificador binário a ser utilizado
# transf_problem - método de tranformação do problema:
# BinaryRelevance, ClassifierChain ou Label Powerset
# Matrizes de entrada e saída para treinamento (xtrain, ytrain)
# Matrizes de entrada e saída parra teste (xtest, ytest)
# Saída:
# result - Dicionário de resultados com acurácia, hamming loss e tempo de execução
def TestarModelo(model_value, transf_problem_value, xtrain, ytrain, xtest, ytest):
  model = model_value[1]
  transf_problem = transf_problem_value[1]
  inicio = time.time()
  clf = transf_problem(model)
  # normalizar os dados
  scaler = MinMaxScaler()
  xtrain = scaler.fit_transform(xtrain)
  xtest = scaler.transform(xtest)
  clf.fit(xtrain, ytrain)
  clf_predictions = clf.predict(xtest)
  acc = accuracy_score(ytest, clf_predictions)
  ham = hamming_loss(ytest, clf_predictions)
  result = {"transf problema": transf_problem_value[0], "modelo": model_value[0],\
  "acuracia:": acc, "hamming_score": ham, "tempo execucao(segs)": time.time()-inicio}
  print(result)
  with open('resultados_transf_problema.txt', 'a') as file:
      file.write(json.dumps(result)) # use `json.loads` to do the reverse
      file.write("\n")
  return result

# Obter Matrizes de Treino (X_train, y_train)  e Teste (X_test, y_test)
# Entradas:
# NumeroDeFeatures - utiizado como filtro de colunas das amostras
# attacks - lista de ataques
# df_imp - data frame das features em ordem de importância
# df_ataques - data frame de ataques
# Saidas:
# Matrizes de treino - X_train, y_train
# Matrizes de Teste - X_test, y_test
def ObterMatrizesTreinoeTeste(NumerodeFeatures, attacks, df_imp, df_ataques):
    # Obter lista das Features em ordem de importância
    ImpFeatures = df_imp['Features'].to_list()[0:NumerodeFeatures]
    # print(ImpFeatures)

    # Selecionar Xfeatures pela ordem de importância
    Xfeatures = df_ataques[ImpFeatures]
    # print(Xfeatures)

    # Obter as colunas correspondentes aos ataques
    y = df_ataques[attacks]
    # print("y.head()")
    # print(y.head())

    # Obter a coluna correspondente a Benigno
    y1 = df_ataques['Benign']
    # print("y1.head()")
    # print(y1.head())

    # Concatenar as colunas de ataques e de Benigno
    y = y.join(y1)
    # print("y.head()")
    # print(y.head())

    # Separar test sets de treinamemto e teste (70% para treino e 30% para teste)
    X_train, X_test, y_train, y_test = train_test_split(Xfeatures, y, test_size=0.3, random_state=42)

    print("type(X_train")
    print(type(X_train))

    print("X_train.shape")
    print(X_train.shape)

    print("y_train.shape")
    print(y_train.shape)

    print("X_test.shape")
    print(X_test.shape)

    print("y_test.shape")
    print(y_test.shape)

    return X_train, y_train, X_test, y_test

# Código retirado de
# https://www.geeksforgeeks.org/python-program-right-rotate-list-n/
# Faz a rotação circular de uma lista a direita
def rightRotate(lists, num):
    output_list = []

    # Will add values from n to the new list
    for item in range(len(lists) - num, len(lists)):
        output_list.append(lists[item])

    # Will add the values before
    # n to the end of new list
    for item in range(0, len(lists) - num):
        output_list.append(lists[item])

    return output_list


if __name__ == "__main__":
    # Obter o tempo inicial
    seconds = time.time()

    # dicionário de classificadores de IA
    dict_classif_bin = {"Nearest Neighbors": KNeighborsClassifier(3), "Random Forest": RandomForestClassifier(max_depth=5, n_estimators=10, n_jobs = -1),\
    "ID3": DecisionTreeClassifier(max_depth=5, criterion="entropy")}

    # dicionário de métodos de transformação do problema
    dict_prod_transf = {"BinaryRelevance": BinaryRelevance, "ClassifierChain": ClassifierChain, "LabelPowerset": LabelPowerset}

    # Lista de Numero de Features a serem consideradas
    ListaNumeroDeFeatures = list(range(20, 80, 20))
    print(ListaNumeroDeFeatures)

    # Obter lista de nomes de arquivos de ataque
    attack_files = os.listdir("attacks")  # It creates a list of file names in the "attacks" folder

    # Obter lista de arquivos reduzidos de ataque prontos para processamento Multi-Label
    reduced_attack_files = os.listdir("multilabels")  # It creates a list of file names in the "attacks" folder

    # Ajustar ordem dos arquivos de 50.000 linhas para 250.000 linhas
    reduced_attack_files = rightRotate(reduced_attack_files, 1)

    # Obter a lista de ataques
    # removendo .csv para cada arquivo da lista de arquivos de ataque
    attacks = fi.Get_List_of_Attacks(attack_files)
    # print(attacks)

    # Criar um Data Frame para as Features da  lista de importancias dos ataques
    df1 = pd.read_csv(".//all_data.csvimportance.csv", low_memory=False)
    # print(df1.head())

    # Se necessário apagar o arquivo de resultados
    # remanescente da execução anterior
    if (os.path.isfile('./resultados_transf_problema.txt')):
        os.remove('./resultados_transf_problema.txt')

    # Aqui começa o loop para testar os modelos para todas as combinações de:
    # NumeroDeFeatures, Número de linhas do Arquivo de Ataque,
    # Método de Transformação do Problema e Classificador
    for NumeroDeFeatures in  ListaNumeroDeFeatures:
      for arquivo_ataque in reduced_attack_files:
        print("\nProcessando "+arquivo_ataque+"\n")
        if arquivo_ataque == "reducedallattackfiles50.ml.csv":
          Str_arquivo_ataque = arquivo_ataque[-9:-7]
        else:
          Str_arquivo_ataque = arquivo_ataque[-10:-7]
        # Criar um data frame parao arquivo de ataque reduzido preparado para processamento Multi_label
        df2 = pd.read_csv(".//multilabels//"+arquivo_ataque, low_memory=False)

        # Obter Matrizes de Treinamento (X_train, y_train) e Teste (X_test, y_test)
        X_train, y_train, X_test, y_test = ObterMatrizesTreinoeTeste(NumeroDeFeatures, attacks, df1, df2)

        with open('resultados_transf_problema.txt', 'a') as file:
          # Escrever cabeçalho no arquivo de saída
          StrCabecalho = "Numero de Features = "+str(NumeroDeFeatures)+" Numero de Linhas = "+Str_arquivo_ataque+".000\n"
          file.write(StrCabecalho)  # use `json.loads` to do the reverse

        # Testar Modelo combinando técnicas de tranformação de problema e classificador de IA
        for value_pt in dict_prod_transf.items():
          print("\n")
          for value_clf in dict_classif_bin.items():
            # Evita executar Nearest Neighbors para alto número de linhas do arquivo
            # devido ao tempo de alto de processamento
            if (value_clf[0] != "Nearest Neighbors") or\
            ((value_clf[0] == "Nearest Neighbors") and (arquivo_ataque != 'reducedallattackfiles250.ml.csv')
            and (arquivo_ataque != 'reducedallattackfiles200.ml.csv')) or\
            ((value_clf[0] == "Nearest Neighbors") and (arquivo_ataque == 'reducedallattackfiles200.ml.csv')
            and (NumeroDeFeatures == 20)):
              TestarModelo(value_clf, value_pt, X_train, y_train, X_test, y_test)

    tempo = time.time() - seconds
    Strtempo = str(tempo)
    StrFecho = "Total operation time: = "+ Strtempo+" seconds"
    with open('resultados_transf_problema.txt', 'a') as file:
        # Escrever fecho do arquivo de saída
        file.write(StrFecho)

    print("mission accomplished!")
    print(StrFecho)

