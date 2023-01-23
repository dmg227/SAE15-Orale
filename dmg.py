import csv
import webbrowser
import matplotlib.pyplot as plt
import numpy as np



#ouvrir le fichier "fichieratraiter.txt"
fichier=open("DumpFile.txt", "r")

#création des listes = Créer des listes pour remplir chacune d'elles avec les données appropriées dans la capture de paquets tcpdump.
ipsr=[]
ipde=[]
longueur=[]
flag=[]
seq=[]
heure=[]

      # créer des compteurs
#compteur du nombre de flag [P] = counter for flag [P] number
flagcounterP=0
#compteur du nombre de flag [S] = counter for flag [S] number
flagcounterS=0
#compteur du nombre de flag [.] = counter for flag [.] number
flagcounter=0
#compteur des trames échangés = counter for number of frames  exchanged on network
framecounter=0
#compteur request = counter for the number of requests
requestcounter=0
#compteur reply = counter for number of replies
replycounter=0
#compteur sequence = sequences counter
seqcounter=0
#compteur acknowledgement = acknowledgments counter
ackcounter=0
#compteur window = windows counter
wincounter=0

for ligne in fichier:
    # make a split with space as delimiter = faire une séparation avec un espace comme délimiteur
    split=ligne.split(" ")
    #delete the hexadecimal blocks and keep only the lines which contain the information
    #supprimez les blocs hexadécimaux et conservez uniquement les lignes contenant les informations.
    if "IP" in ligne :
    #filling the flag list
    #remplissage de la liste drapeau    
        framecounter+=1
        if "[P.]" in ligne :
            flag.append("[P.]")
            flagcounterP+=1
        if "[.]" in ligne :
            flag.append("[.]")
            flagcounter+=1
        if "[S]" in ligne :
            flag.append("[S]")
            flagcounterS+=1
        #filling the seq list
        #remplir la liste seq
        if "seq" in ligne :
            seqcounter+=1
            seq.append(split[8])
        #counting windows
        ##comptage des fenêtres
        if "win" in ligne :
            wincounter+=1
        #counting acks 
        #comptage d'accusé de réception
        if "ack" in ligne:
            ackcounter+=1
            
        #filling the IP source(ipsr) list
        #Remplissage de la liste des sources IP (ipsr)
        ipsr.append(split[2])  
        #filling the IP destination(ipde) list
        #Remplissage de la liste des destinations IP (ipsr)
        ipde.append(split[4])
        #filling the hour (heure) list
        #remplissage de la liste des heures
        heure.append(split[0])
        #filling the lenght (longueur) list
        #remplir la liste de longueur
        if "length" in ligne:
            split = ligne.split(" ")
            if "HTTP" in ligne :
                longueur.append(split[-2])
            else: 
                longueur.append(split[-1]) 
        #to detect request and reply via ICMP protocol
        #détecter les requêtes et les réponses via le protocole ICMP.
        if "ICMP" in ligne:
            if "request" in ligne:
                requestcounter+=1
            if "reply" in ligne:
                replycounter+=1
'''ipsource2 = []
ipdesti2 = []   
ipdestifinale=[]             
                
for i in ipsr:
    if not "." in i:
        ipsource2.append(i)
    elif "ssh" in i or len(i) > 15 or "B" in i:
        ports = i.split(".")
        del ports[-1]
        delim = "."
        delim = delim.join(ports)
        ipsource2.append(delim)
    else:
        ipsource2.append(i)
for j in ipde:
    if not "." in j:
        ipdesti2.append(j)
    elif "ssh" in j or len(j) > 15 or "B" in j:
        ports = j.split(".")
        del ports[-1]
        delim = "."
        delim = delim.join(ports)
        ipdesti2.append(delim)
    else:
        ipdesti2.append(j)

for l in ipdesti2:
    if not ":" in l:
        ipdestifinale.append(l)
    else:
        deuxp = l.split(":")
        ipdestifinale.append(deuxp[0])   '''

             
globalflagcounter=flagcounter+flagcounterP+flagcounterS

P=flagcounterP/globalflagcounter
S=flagcounterS/globalflagcounter
A=flagcounter/globalflagcounter 

globalreqrepcounter=replycounter+requestcounter
req=requestcounter/globalreqrepcounter
rep=replycounter/globalreqrepcounter
          
#transform all counters into lists to view them on the csv file
#transformer tous les compteurs en listes pour les afficher dans le fichier csv 
flagcounter=[flagcounter]
flagcounterP=[flagcounterP]
flagcounterS=[flagcounterS]
framecounter=[framecounter]
requestcounter=[requestcounter]
replycounter=[replycounter]
seqcounter=[seqcounter]
ackcounter=[ackcounter]
wincounter=[wincounter]



# create python graphic with matplotlib library 
#créer un graphe avec la bibliothèque matplotlib
  #circular graphic for flags
  #graphe circulaire pour les flags
name = ['Flag [.]', 'Flag [P]', 'Flag [S]']
data = [A,P,S]

explode=(0, 0, 0)
plt.pie(data, explode=explode, labels=name, autopct='%1.1f%%', startangle=90, shadow=True)
plt.axis('equal')
plt.savefig("graphe1.png")
plt.show()
  #circular graphic for request and reply 
  #graphe circulaire pour les requêtes et réponses
name2 = ['Request' , 'Reply']
data2 = [req,rep]  
explode=(0,0)
plt.pie(data2,explode=explode,labels=name2, autopct='%1.1f%%',startangle=90, shadow=True)
plt.savefig("graphe2.png")
plt.show()

#contenu de la page web = web page content 
htmlcontenu='''

<html lang="fr">
   <head>
      <meta charset="utf-8">
      <title> Traitement des données </title>
      <style>
      body{
             
          background-image: url('https://cdn.pixabay.com/photo/2019/07/16/06/43/fantasy-4341168_960_720.jpg');
          background-repeat: no-repeat;
          background-size: cover;
          color:#e5f2f7;
          background-attachment: fixed;
          }
      </style>
   </head>
   
   <body>
       <center><h1>Demba Moussa Gaharo B2</h1></center>
       <center><h2>Projet SAE 15</h2></center>
       <center><p>Sur cette page web on va vous présenter les infomations et données petinentes qu'on a trouvé dans le fichier à traiter </p></center>
       <center><h3> Nombre total des trames échangés</h3> %s</center>
       <br>
       <center><h3> Drapeaux (Flags)<h3></center>
       <center>Nombre de flags [P] (PUSH) = %s
       <br>Nombre de flags [S] (SYN) = %s  
       <br>Nombre de flag [.] (ACK) = %s
       <br>
       <br>
       <img src="graphe1.png">
       <h3> Nombre des requests et replys </h3>
       Request = %s 
       <br>
       Reply = %s
       <br>
       <br>
       <img src="graphe2.png">
       <h3>Statistiques entre seq et win et ack </h3>
       Nombre de seq = %s
           <br>
       Nombre de win = %s
           <br>
       Nombre de ack = %s
       
      
   </body>

</html>
'''%(framecounter,flagcounterP,flagcounterS,flagcounter,requestcounter,replycounter,seqcounter,wincounter,ackcounter)

#ouverture d'un fichier csv = open a csv file for data extracted from txt file untreated 
with open('moussa.csv', 'w', newline='') as fichiercsv:
    writer = csv.writer(fichiercsv)
    writer.writerow(['Heure','IP source','IP destination','Flag','Seq','Length'])
    writer.writerows(zip(heure,ipsr,ipde,flag,seq,longueur))
    fichiercsv.close()
    
#ouverture d'un fichier csv    = open a csv file for different stats
with open('demba.csv', 'w', newline='') as fichier2:
    writer = csv.writer(fichier2)
    writer.writerow(['Flag[P] (PUSH)','Flag[S] (SYN)','Flag[.] (ACK)','Nombre total de trames',"nombre de request","nombre de reply","nombre de sequence","nombre de acknowledg","nombre de window"])
    writer.writerows(zip(flagcounterP,flagcounterS,flagcounter,framecounter,requestcounter,replycounter,seqcounter,ackcounter,wincounter))
    fichier2.close()
    
#partie page  web = open a web page with important information and statistics
with open("demba.html","w") as html:
    html.write(htmlcontenu)
    print("page web créée avec succès")

       
fichier.close()
