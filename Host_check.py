import nmap
#nmap -Pn -sA -p 22 192.168.1.5 --disable-arp-ping
#10.10.2.18

class ssh_scan:
	def __init__(self):
	 self.nm = nmap.PortScanner()
	
	def scan(self,ip,port):
		self.nm.scan(ip,port,'-O -PA --disable-arp-ping')
		self.nm._scan_result

	def p_scan(self):
		ip_l = list(self.nm._scan_result['scan'].keys())
		m_list = {
			'vendor':'null',
			'ip':'null',
			'mac':'null',
			'tcp_name':'null',
			'tcp_state':'null',
			'version':'null'
		}
		file = open('scan.txt','a')
		file.write('vendor;ip;mac;tcp_name;tcp_state;version\n')
		for i in ip_l:
			print(i)
			try:
				m_list['vendor'] = str(self.nm._scan_result['scan'][i]['vendor'][ self.nm._scan_result['scan'][i]['addresses']['mac'] ])
			except:
				m_list['vendor'] = 'null'
			try:
				m_list['ip'] = str(self.nm._scan_result['scan'][i]['addresses']['ipv4'])
			except:
				m_list['ip'] = 'null'
			try:
				m_list['mac'] = str(self.nm._scan_result['scan'][i]['addresses']['mac'])
			except:
				m_list['mac'] = 'null'
			try:
				m_list['tcp_name'] = str(self.nm._scan_result['scan'][i]['tcp'][22]['name'])
			except:
				m_list['tcp_name'] = 'null'
			try:
				m_list['tcp_state'] = str(self.nm._scan_result['scan'][i]['tcp'][22]['state'])
			except:
				m_list['tcp_state'] = 'null'
			try:
				m_list['version'] = str(self.nm._scan_result['scan'][i]['tcp'][22]['version'])
				if m_list['version'] == '':
					m_list['version'] = 'null'
			except:
				m_list['version'] = 'null'

			file.write(m_list['vendor'] +';'+ m_list['ip'] +';'+ m_list['mac'] +';'+ m_list['tcp_name'] +';'+ m_list['tcp_state'] +';'+ m_list['version']+'\n')
			print(m_list)
		file.close()


#ip = input('ip or range: \n')

ip ='192.168.1.0/24'
port = '22'

ssh_scan = ssh_scan()

ssh_scan.scan(ip,port)
ssh_scan.p_scan()

#scan1 = ssh_scan.nm._scan_result
#print(scan1)



