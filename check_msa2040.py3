#!/usr/bin/python
import sys, getopt, urllib.request, urllib.parse, urllib.error, urllib.request, urllib.error, urllib.parse, hashlib, ssl
import xml.etree.ElementTree as ET

class StaticOutput:
    author = "Written by Alexandru Asofroniei (alex@aso.re)"
    version = "1.0 Production"
    about = "This python program checks the status of the HPE MSA2040 Storage system using the XML API."
    usage = "Options:\n\t-h,--help - display this message\n\t-n, --hostname= - IP or hostname of the storage\n\t-u, --username= - Username to connect to the storage\n\t-p --password = - Password to connect to the storage\n\t-c, --check= - What to check. Valid options are: events last <nb>, controllers, power-supplies, sensor-status, system. \n\t-v, --version - print the version"

class StaticCommands:
    @staticmethod
    def authenticate(hn, lu, un, pss): #hn = hostname; lu = loginURL; un = userName; pss = password
        """Authenticate using to the storage using the API. 
        Return the response that contains the session key."""
        #Accept self-signed certificate
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        credentialString = un + "_" + pss
        credentials = hashlib.md5(credentialString.encode()).hexdigest()
        url = "https://" + hn + lu + credentials
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req, context=ctx)
        return response.read()
    @staticmethod
    def requestStatus(hn, au, ch, at): # hn = hostname, au = apiURL, ch = checkPath, at = authToken
        """Send the API request to the method passed in as ch. Return the response."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = "https://"+hn+au+ch
        req = urllib.request.Request(url)
        req.add_header('sessionkey', at)
        response = urllib.request.urlopen(req, context=ctx)
        return response.read()
    @staticmethod
    def logout(hn, lu, at): # hn = hostname, lu = logoutURL, at = authToken
        """Logout the user using the API."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = "https://" + hn + lu + at
        req = urllib.request.Request(url)
        req.add_header('sessionkey', at)
        response = urllib.request.urlopen(req, context=ctx)
        return response.read()
    @staticmethod
    def processEvents(resp):
        """Parse the API response containing the events and return the severity, 
        message and nagios exit code."""
        result = ""
        exitc = 0
        countW = 0
        countE = 0
        countI = 0
        root = ET.fromstring(resp)
        for child in root:
            for prop in child:
                if 'display-name' in prop.attrib:
                    if prop.attrib['name'] in 'severity':
                        if "WARNING" in prop.text:
                            countW += 1
                        elif "ERROR" in prop.text or "CRITICAL" in prop.text:
                            countE += 1
                        elif "INFORMATIONAL" in prop.text:
                            countI += 1
                        result += prop.text + ": "
                    elif prop.attrib['name'] in 'message':
                        result += prop.text + "<br>"
        result += "<br>"
        if countE > 0:
            exitc = 2
        elif countW > 0:
            exitc = 1
        return result, exitc
    @staticmethod
    def hardwareStatus(resp):
        """Parse the API response containing the status of different hardware elements 
        and return the data and nagios exit code."""
        result = ""
        exitc = 0
        root = ET.fromstring(resp)
        for child in root:
            for prop in child: 
                if 'display-name' in prop.attrib:
                    if isinstance(prop.text, str):
                        result += prop.attrib['display-name'] + ": " + prop.text.encode('ascii', 'ignore') + "<br>"
                        if prop.attrib['display-name'] in "Health":
                            if "0" not in prop.text and "OK" not in prop.text:
                                exitc = 2
            result += "----<br>"
        return result, exitc
    @staticmethod
    def sensorStatus(resp):
        """Parse the API response containing the status of the sensors 
        and return the data and nagios exit code."""
        result = ""
        exitc = 2
        root = ET.fromstring(resp)
        for child in root:
            for prop in child: 
                if 'display-name' in prop.attrib:
                    if isinstance(prop.text, str):
                        result += prop.attrib['display-name'] + ": " + prop.text.encode('ascii', 'ignore') + "<br>"
                        if "Status" in prop.attrib['display-name'] and "OK" in prop.text:
                            exitc = 0
                        elif "Status" in prop.attrib['display-name'] and "1" in prop.text:
                            exitc = 0
            result += "----<br>"
        return result, exitc
    @staticmethod
    def systemInformation(resp):
        """Parse the API response containing the system information 
        and return the data and nagios exit code."""
        result = ""
        exitc = 2
        root = ET.fromstring(resp)
        for child in root:
            for prop in child: 
                if 'display-name' in prop.attrib:
                    if isinstance(prop.text, str):
                        result += prop.attrib['display-name'] + ": " + prop.text.encode('ascii', 'ignore') + "<br>"
                        if "Health" in prop.attrib['display-name'] and "OK" in prop.text:
                            exitc = 0
                        elif "Health" in prop.attrib['display-name'] and "1" in prop.text:
                            exitc = 0
            result += "----<br>"
        return result, exitc

def main(argv):
    exitCode = 3
    hostname = ""
    apiURL = "/api/show/"
    loginURL = "/api/login/"
    logoutURL = "/api/logout/"
    userName = ""
    password = ""
    command = ""
    output = ""
    debug = 0


    #parse program arguments
    opts, args = getopt.getopt(argv, "hvn:u:p:c:",["help", "version", "hostname=", "username=", "password=", "check="])
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(StaticOutput.about)
            print(StaticOutput.usage)
            sys.exit(exitCode)
        elif opt in ("-v", "--version"):
            print(StaticOutput.version)
            print(StaticOutput.author)
            sys.exit(exitCode)
        elif opt in ("-n","--hostname"):
            hostname = arg
        elif opt in ("-u", "--username"):
            userName = arg
        elif opt in ("-p", "--password"):
            password = arg
        elif opt in ("-c", "--check"):
            command = arg
        else:
            print(StaticOutput.about)
            print(StaticOutput.usage)
            sys.exit(exitCode)
    
    if hostname not in "" and userName not in "" and password not in "" and command not in "":
        response = StaticCommands.authenticate(hostname, loginURL, userName, password)
        if debug == 1:
            print(response) 
        root = ET.fromstring(response)
        if 'Unsuccessful' in root[0][2].text:
            print("Authentication Unsuccessful: The provided credentials are bad.")
            sys.exit(exitCode)
        else:
            sessionKey = root[0][2].text #This is based on the response received from the MSA2040

        #Available commands are: events last <nb>, controllers, volume-statistics, power-supplies, sensor-status, system
        if "events last" in command:
            commandArray = command.split(" ")
            if len(commandArray) == 3:
                output, exitCode = StaticCommands.processEvents(StaticCommands.requestStatus(hostname, apiURL, "events/last/"+commandArray[2], sessionKey))
                if exitCode == 0:
                    output = "No errors detected.<br>More info in the extended view.\n" + output
                else:
                    output = "Errors have been detected.<br>More info in the extended view.\n" + output
                response = StaticCommands.logout(hostname, logoutURL, sessionKey)
                print(output)
                sys.exit(exitCode)

        if "controllers" in command:
            output, exitCode = StaticCommands.hardwareStatus(StaticCommands.requestStatus(hostname, apiURL, "controllers", sessionKey))
            if exitCode == 0:
                output = "Controllers status is OK.<br>More info in the extended view.\n" + output
            else:
                output = "Controllers status is degraded.<br>More info in the extended view.\n" + output
            response = StaticCommands.logout(hostname, logoutURL, sessionKey)
            print(output)
            sys.exit(exitCode)

        if "power-supplies" in command:
            output, exitCode = StaticCommands.hardwareStatus(StaticCommands.requestStatus(hostname, apiURL, "power-supplies", sessionKey))
            if exitCode == 0:
                output = "Power supplies status is OK.<br>More info in the extended view.\n" + output
            else:
                output = "Power supplies status is degraded.<br>More info in the extended view.\n" + output
            response = StaticCommands.logout(hostname, logoutURL, sessionKey)
            print(output)
            sys.exit(exitCode)
        
        if "sensor-status" in command:
            output, exitCode = StaticCommands.sensorStatus(StaticCommands.requestStatus(hostname, apiURL, "sensor-status", sessionKey))
            if exitCode == 0:
                output = "Sensor status is OK.<br>More info in the extended view.\n" + output
            else:
                output = "Sensor status is over threshold.<br>More info in the extended view.\n" + output
            response = StaticCommands.logout(hostname, logoutURL, sessionKey)
            print(output)
            sys.exit(exitCode)

        if "system" in command:
            output, exitCode = StaticCommands.systemInformation(StaticCommands.requestStatus(hostname, apiURL, "system", sessionKey))
            if exitCode == 0:
                output = "System health is OK.<br>More info in the extended view.\n" + output
            else:
                output = "System health is degraded.<br>More info in the extended view.\n" + output
            response = StaticCommands.logout(hostname, logoutURL, sessionKey)
            print(output)
            sys.exit(exitCode)
    
        #Logout after job is done
        response = StaticCommands.logout(hostname, logoutURL, sessionKey)
    print("You are missing a required option.")
    print(StaticOutput.usage)

    sys.exit(exitCode)


if __name__ == "__main__":
    main(sys.argv[1:])

