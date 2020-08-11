from database_handler import DatabaseHandler
import os

DEBUG = 'DEBUG' in os.environ

class TransactionHandler:
    def __init__(self, username, localip):
        self.dbhandle = DatabaseHandler()
        self.scanning_event = {
            'openports': {},
            'closed_ports': [],
            'os': 'unknown'
        }
        self.exploit_events = []
        self.post_exploit_events = []
        self.username = username
        self.system_ip = localip
        self.os = "unknown"
        self.scanning_record = None
    
    def set_open_ports(self, open_ports: dict):
        if DEBUG:
            print("Open Ports for " + self.username + "("+ self.system_ip +"): " + str(open_ports))
        self.scanning_event['openports'] = open_ports
    
    def set_cves(self, cves_data: dict):
        for port, port_cves in cves_data.items():
            try:
                self.scanning_event['openports'][str(port)]['cves'] = port_cves
            except Exception as e:
                print("Cannot find Key for Port " + str(port))
            
    
    def set_os(self, os_str):
        self.os = os_str

    def set_closed_ports(self, closed_ports: list):
        self.scanning_event['closed_ports'] = closed_ports
    
    def add_exploit_event(self, exploit:str, payload:str, engine:str, success:bool, port:int, result:dict):
        self.exploit_events.append({'exploit': exploit, 'payload': payload, 'engine': engine, 'success': success, 'result': result, 'port': port})

    def clear_exploit_events(self):
        self.exploit_events.clear()
    
    def add_post_exploit_event(self, post_exploit:str, success: bool, data: str, engine: str):
        self.post_exploit_events.append({'post': post_exploit, 'data': data, 'success': success, 'engine': engine})
    
    def update_db(self):
        self.scanning_record = self.dbhandle.insert_scanning_log(self.scanning_event['openports'], self.username, self.system_ip, self.os, self.scanning_event['closed_ports'])['event']
        if DEBUG:
            print("Adding Scanning Record: " + str(self.scanning_record))
        if self.exploit_events != []:
            for event in self.exploit_events:
                exploit_record = self.dbhandle.insert_exploitation_log(self.username, self.system_ip, event['exploit'], event['payload'], event['engine'], str(event['port']), event['success'], self.scanning_record)
                if DEBUG:
                    print("Exploiting Record: " + str(exploit_record.values()))
                # event['result']['exploit_event'] = exploit_record
        if self.post_exploit_events != []:
            for event in self.post_exploit_events:
                post_exploit_record = self.dbhandle.insert_post_exploitation_log(self.username,self.system_ip, event['post'], event['data'], event['engine'], event['success'], self.scanning_record)
                if DEBUG:
                    print("Post Exploitation Record: " + str(exploit_record.values()))

    
    
