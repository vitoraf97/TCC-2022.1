# Demo para Processamento de Inteligencia Artificial Multi-Label para detecção de Ataques
# utilizando a técnica de adaptação
# Nome: MultiLabel.py
# Nome do Aluno: Vitor de Avila Falcão
# Matricula: 2019201206
# Curco: Ciência da Computação - Unicarioca - Rio Comprido
# Disciplina: TCC 2022.1
# Data: 23/04/2022
# Orientador: Prof Fabio Henrique Silva
# pré-condições:
# Os arquivos com ataques separados devem estar no diretório ./attacks
# O arquivo com as lista de importâncias devem estar no diretório ./
# arquivo all_data.csvimportance.csv - Lista de importâncias para o processamento de um único arquivo com todos os ataques
# Os arquivos de ataques reduzidos preparados para o processamento Multi-Label devem ser colocardos no Diretório ./multilabels
# ex: reducedallattackfiles100.ml.csv
# Demo para: 60 Features, 50.000 linhas e BR-KNN

import os
import time
import pandas as pd
import FeaturesImportance as fi
import ProblemTransformation as pt
import json


from sklearn.metrics import accuracy_score,hamming_loss
from sklearn.model_selection import GridSearchCV
from skmultilearn.adapt import MLkNN
from skmultilearn.adapt import BRkNNaClassifier



def ConverterDftoArrays(X_train, y_train, X_test, y_test):
  Xarr_train = X_train.to_numpy()
  print(type(Xarr_train))
  print(Xarr_train.shape)
  Xarr_test = X_test.to_numpy()
  print(type(Xarr_test))
  print(Xarr_test.shape)
  yarr_train = y_train.to_numpy()
  print(type(yarr_train))
  print(yarr_train.shape)
  yarr_test = y_test.to_numpy()
  print(type(yarr_test))
  print(yarr_test.shape)

  return Xarr_train, yarr_train, Xarr_test, yarr_test

# Testar o modelo de classificação com um método de adaptação
# para classificação multi-label
# Entradas:
# model_Value - classificador  a ser utilizado
# parametros - parametros do classificador
# score - estratégia para cáculo do score de treinamento
# Matrizes de entrada e saída para treinamento (Xarr_train, yarr_train)
# Matrizes de entrada e saída parra teste (Xarr_test, yarr_test)
# Saída:
# result - Dicionário de resultados com acurácia, hamming loss e tempo de execução
def TestarModeloAdaptado(modelo_value, parametros, score, Xarr_train, yarr_train, Xarr_test, yarr_test):
  modelo = modelo_value[1]
  start = time.time()
  clf = GridSearchCV(modelo, parametros, scoring=score)
  clf.fit(Xarr_train, yarr_train)
  time_training = time.time() - start
  print('training time taken: ', time_training, 'seconds')
  print('best parameters :', clf.best_params_, 'best score: ',
        clf.best_score_)
  training_result = {'best parameters' : clf.best_params_, 'best score':  clf.best_score_, \
  'training time taken' :  time_training}
  clf_predictions = clf.predict(Xarr_test)
  acc = accuracy_score(yarr_test, clf_predictions)
  ham = hamming_loss(yarr_test, clf_predictions)
  result = {"modelo": modelo_value[0], \
            "acuracia:": acc, "hamming_score": ham, "tempo execucao(segs)": time.time() - start}
  print(result)
  with open('resultados_adaptados.txt', 'a') as file:
      file.write("\n")
      file.write(json.dumps(training_result))  # use `json.loads` to do the reverse
      file.write(json.dumps(result))  # use `json.loads` to do the reverse
      file.write("\n")
  return result


if __name__ == "__main__":

    # Obter o tempo inicial
    seconds = time.time()

    # dicionário de classificadores de IA Muiti-Label adaptados
    #dict_classif_ml_adapted = {"ML-KNN": MLkNN(),
    #                  "BR-KNNa": BRkNNaClassifier()}

    dict_classif_ml_adapted = {"BR-KNNa": BRkNNaClassifier()}

    #dict_classif_ml_parametros = {"ML-KNN": {'k': range(1, 3), 's': [0.5, 0.7, 1.0]},
    #                          "BR-KNNa": {'k': range(3, 5)}}

    dict_classif_ml_parametros = {"BR-KNNa": {'k': range(3, 5)}}


    # Lista de Numero de Features a serem consideradas
    #ListaNumeroDeFeatures = list(range(20, 80, 20))
    ListaNumeroDeFeatures = list(range(60, 80, 20))
    print(ListaNumeroDeFeatures)

    # Obter lista de nomes de arquivos de ataque
    attack_files = os.listdir("attacks")  # It creates a list of file names in the "attacks" folder

    # Obter lista de arquivos reduzidos de ataque prontos para processamento Multi-Label
    reduced_attack_files = os.listdir("multilabels")  # It creates a list of file names in the "attacks" folder

    # Ajustar ordem dos arquivos de 50.000 linhas para 250.000 linhas
    red_attack_files = pt.rightRotate(reduced_attack_files, 1)

    # Pegar até 150.000 linhas
    reduced_attack_files = red_attack_files[0:3]
    #reduced_attack_files = red_attack_files[0:1]

    # Adaptação para Demo
    reduced_attack_files = red_attack_files[0:1]
    print('Teste Demo para 50.000 Linhas')
    print(reduced_attack_files)

    # Obter a lista de ataques
    # removendo .csv para cada arquivo da lista de arquivos de ataque
    attacks = fi.Get_List_of_Attacks(attack_files)
    # print(attacks)

    # Criar um Data Frame para as Features da  lista de importancias dos ataques
    df1 = pd.read_csv(".//all_data.csvimportance.csv", low_memory=False)
    # print(df1.head())

    # Se necessário apagar o arquivo de resultados
    # remanescente da execução anterior
    if (os.path.isfile('./resultados_adaptados.txt')):
        os.remove('./resultados_adaptados.txt')

        # Aqui começa o loop para testar os modelos para todas as combinações de:
        # NumeroDeFeatures, Número de linhas do Arquivo de Ataque,
        # e Classificador por Adaptação
    for NumeroDeFeatures in ListaNumeroDeFeatures:
        for arquivo_ataque in reduced_attack_files:
            print("\nProcessando " + arquivo_ataque + "\n")
            if arquivo_ataque == "reducedallattackfiles50.ml.csv":
                Str_arquivo_ataque = arquivo_ataque[-9:-7]
            else:
                Str_arquivo_ataque = arquivo_ataque[-10:-7]
            # Criar um data frame parao arquivo de ataque reduzido preparado para processamento Multi_label
            df2 = pd.read_csv(".//multilabels//" + arquivo_ataque, low_memory=False)

            # Obter Matrizes de Treinamento (X_train, y_train) e Teste (X_test, y_test)
            X_train, y_train, X_test, y_test = pt.ObterMatrizesTreinoeTeste(NumeroDeFeatures, attacks, df1, df2)

            Xarr_train, yarr_train, Xarr_test, yarr_test = ConverterDftoArrays(X_train, y_train, X_test, y_test)

            with open('resultados_adaptados.txt', 'a') as file:
                # Escrever cabeçalho no arquivo de saída
                StrCabecalho = "Numero de Features = " + str(
                    NumeroDeFeatures) + " Numero de Linhas = " + Str_arquivo_ataque + ".000\n"
                file.write(StrCabecalho)  # use `json.loads` to do the reverse

            for value_ml in dict_classif_ml_adapted.items():
                print("\n")
                #score = 'f1_micro'
                score = 'f1_weighted'
                parametros =  dict_classif_ml_parametros[value_ml[0]]
                result = TestarModeloAdaptado(value_ml, parametros, score, Xarr_train, yarr_train, Xarr_test, yarr_test)

    tempo = time.time() - seconds
    Strtempo = str(tempo)
    StrFecho = "Total operation time: = " + Strtempo + " seconds"
    with open('resultados_adaptados.txt', 'a') as file:
        # Escrever fecho do arquivo de saída
        file.write(StrFecho)

    print("mission accomplished!")
    print(StrFecho)

