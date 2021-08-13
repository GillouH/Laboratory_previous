from laboratoryTools.network import serverAddress, Socket, ServerSocket, ClientSocket
from tkinter import Tk, StringVar, Frame, Button, Label, Entry, Text, Scrollbar # Classes used
from tkinter.font import Font
from tkinter import NORMAL, DISABLED    # Widget State Constants
from threading import Thread, currentThread
from select import select
from tkinter import INSERT, END # Index Constant for Text
from tkinter import NSEW, NS    # Fill Direction Size Constant
from tkinter import LEFT, RIGHT # Widget side display Constant
from tkinter import VERTICAL    # Scrollbar Direction Constant
from laboratoryTools.logging import logger
from os.path import isfile
from json import loads, dumps
from enum import Enum, auto


class ClientWindow(Tk):
    BASE_TITLE:"str" = "Client"
    CONNECTION:"str" = "Connection"
    CONNECTING:"str" = "Connecting..."
    CONNECTED:"str" = "Connected"
    DISCONNECTION:"str" = "Disconnection"
    DISCONNECTED:"str" = "Disconnected"

    MEMORY_FILE_NAME:"str" = "memory.json"
    IP:"str" = "IP"
    PORT:"str" = "PORT"
    NAME:"str" = "NAME"
    MEMORY_JSON_KEY:"dict[str,str]" = {}
    for key in [IP, PORT, NAME]:
        MEMORY_JSON_KEY[key]:"str" = "_".join(["MEMORY_JSON_KEY", key])

    MAX_PORT:"int" = 65535
    MAX_IP:"int" = 255

    WEIGHT:"int" = 1

    ErrNoMsgDict:"dict[int,str]" = {
        10060: "The IP address seems wrong.",
        10061: "The Port seems wrong."
    }

    class MSG_STATUT(Enum):
        SEND = auto()
        RECV = auto()
        LOG_INFO = auto()
        LOG_ERROR = auto()

    def __init__(self):
        super().__init__()

        self.FONT:"Font" = Font(root=self, size=15)
        self.serverConfigWidget:"list[Widget]" = []
        self.isConnected:"bool" = False

        self.nameTextVariable:"StringVar" = StringVar()
        self.nameTextVariable.trace_add(mode="write", callback=self.updateConnectionButtonState)

        self.portTextVariable:"StringVar" = StringVar()
        self.portTextVariable.trace_add(mode="write", callback=self.updateConnectionButtonState)

        self.IPTextVariableList:"list[StringVar]" = [StringVar() for IPValue in serverAddress[0].split(sep=".")]
        for IPTextVariable in self.IPTextVariableList:
            IPTextVariable.trace_add(mode="write", callback=self.updateConnectionButtonState)

        self.inputTextVariable:"StringVar" = StringVar()
        self.inputTextVariable.trace_add(mode="write", callback=self.updateSendButtonState)

        self.setTitle(info=ClientWindow.DISCONNECTED)
        self.createServerFrame(master=self, row=0, column=0)
        self.createMessageFrame(master=self, row=1, column=0)

        self.grid_rowconfigure(index=1, weight=ClientWindow.WEIGHT)
        self.grid_columnconfigure(index=0, weight=ClientWindow.WEIGHT)

        self.restoreData()

    def isAbleToConnect(self)->"bool":
        textVariableList:"list[StringVar]" = self.IPTextVariableList + [self.portTextVariable, self.nameTextVariable]
        return not self.isConnected and not False in list(map(lambda textVariable: textVariable.get() != "", textVariableList))
    def updateConnectionButtonState(self, *paramList, **paramDict):
        self.connectButton.config(state=NORMAL if self.isAbleToConnect() else DISABLED)

    def isAbleToSend(self)->"bool":
        return self.isConnected and self.inputTextVariable.get() != ""
    def updateSendButtonState(self, *paramList, **paramDict):
        self.sendButton.config(state=NORMAL if self.isAbleToSend() else DISABLED)

    def setTitle(self, info:"str"):
        self.title(string="{} - {}".format(ClientWindow.BASE_TITLE, info))

    def createFrame(self, row:"int"=None, column:"int"=None, sticky:"str"=None, side:"str"=None, padx:"int"=None, *paramList, **paramDict)->"Frame":
        frame:"Frame" = Frame(*paramList, **paramDict)
        if side is not None or padx is not None:
            frame.pack(side=side, padx=padx)
        else:
            frame.grid(row=row, column=column, sticky=sticky, padx=padx)
        return frame

    def displayMsg(self, msg:"str", msgStatut:"MSG_STATUT"):
        startIndex = self.showText.index(index=INSERT)
        self.showText.config(state=NORMAL)
        self.showText.insert(index=END, chars="{}\n".format(msg))
        self.showText.config(state=DISABLED)
        self.showText.see(index=END)
        stopIndex = self.showText.index(index=INSERT)
        self.showText.tag_add(msgStatut.name, startIndex, stopIndex)

    def listenServerThreadRunMethod(self):
        while self.isConnected:
            socketList, wList, xList = select([self.clientSocket], [], [], ClientSocket.SELECT_TIMEOUT)
            for socketWithMsg in socketList:
                try:
                    msgReceivedList:"list[str]" = socketWithMsg.recv_s(bufferSize=1024)
                    for msgReceived in msgReceivedList:
                        addr:"tuple[str,int]" = socketWithMsg.getpeername()
                        self.displayMsg(msg="<<{}".format(msgReceived), msgStatut=ClientWindow.MSG_STATUT.RECV)
                        if msgReceived in (ServerSocket.STOP_SERVER, Socket.MSG_DISCONNECTION):
                            self.disconnection()
                except ConnectionResetError:
                    self.disconnection()

    def connectionThreadRunMethod(self):
        try:
            ip, port = self.getIP(), int(self.portTextVariable.get())
            self.displayMsg(msg="Connection to {}:{}...".format(ip, port), msgStatut=ClientWindow.MSG_STATUT.LOG_INFO)
            for widget in self.serverConfigWidget:
                widget.config(state="readonly")
            self.connectButton.config(text=ClientWindow.CONNECTING, state=DISABLED)
            self.setTitle(info=ClientWindow.CONNECTING)

            self.clientSocket:"ClientSocket" = ClientSocket(name=self.nameTextVariable.get())
            self.clientSocket.connect(address=(ip, port))

            self.connectButton.config(text=ClientWindow.DISCONNECTION, command=self.disconnection, state=NORMAL)
            self.setTitle(info=ClientWindow.CONNECTED)
            self.isConnected = True
            self.updateSendButtonState()

            self.listenServerThread:"Thread" = Thread(target=self.listenServerThreadRunMethod)
            self.listenServerThread.start()
            self.inputTextEntry.focus()
            self.displayMsg(msg="Connected to {}.".format(self.clientSocket.name), msgStatut=ClientWindow.MSG_STATUT.LOG_INFO)
        except Exception as e:
            logger.error(msg=e)
            for widget in self.serverConfigWidget:
                widget.config(state=NORMAL)
            self.connectButton.config(text=ClientWindow.CONNECTION, state=NORMAL)
            self.setTitle(info=ClientWindow.DISCONNECTED)
            self.isConnected = False
            self.updateSendButtonState()
            errorMsg = "{} {}".format(
                ClientSocket.ConnectionUnableErrorMsg,
                ClientWindow.ErrNoMsgDict[e.errno] if e.errno in ClientWindow.ErrNoMsgDict.keys() else e
            )
            self.displayMsg(msg=errorMsg, msgStatut=ClientWindow.MSG_STATUT.LOG_ERROR)

    def disconnection(self):
        logger.info(msg="Disconnection from {}".format(self.clientSocket))
        self.displayMsg(msg="Disconnection from {}.".format(self.clientSocket.name), msgStatut=ClientWindow.MSG_STATUT.LOG_INFO)
        self.isConnected = False
        if currentThread() != self.listenServerThread:
            self.listenServerThread.join()
        self.clientSocket.close()

        self.setTitle(info=ClientWindow.DISCONNECTED)
        self.connectButton.config(text=ClientWindow.CONNECTION, command=self.connection)
        for widget in self.serverConfigWidget:
            widget.config(state=NORMAL)
        self.updateSendButtonState()

    def connection(self):
        thread:"Thread" = Thread(target=self.connectionThreadRunMethod)
        thread.start()

    # Callbacks to check inputs for PORT/IP entries
    def checkInputIsInt(self, input:"str", max:"int")->"bool":
        try:
            number:"int" = int(input)
            return number >= 0 and number <= max
        except Exception as e:
            logger.error(msg=e)
            return input == ""
    def checkPortInput(self, input:"str")->"bool":
        return self.checkInputIsInt(input=input, max=ClientWindow.MAX_PORT)
    def checkIPInput(self, input:"str")->"bool":
        return self.checkInputIsInt(input=input, max=ClientWindow.MAX_IP)

    def createPortFrame(self, master:"Widget", side:"str"):
        frame:"Frame" = self.createFrame(master=master, side=side, padx=50)
        Label(master=frame, text="PORT: ", font=self.FONT).grid(row=0, column=0)
        entry:"Entry" = Entry(master=frame, textvariable=self.portTextVariable, width=len(str(object=ClientWindow.MAX_PORT)), font=self.FONT, justify=RIGHT)
        entry.grid(row=0, column=1)
        entry.config(validate="key", validatecommand=(self.register(func=self.checkPortInput), "%P"))
        self.serverConfigWidget.append(entry)

    def createIPFrame(self, master:"Widget", side:"str"):
        frame:"Frame" = self.createFrame(master=master, side=side)
        Label(master=frame, text="IP: ", font=self.FONT).grid(row=0, column=0)
        width:"int" = len(str(object=ClientWindow.MAX_IP))
        for i in range(len(self.IPTextVariableList)):
            entry:"Entry" = Entry(master=frame, textvariable=self.IPTextVariableList[i], width=width, font=self.FONT, justify=RIGHT)
            entry.grid(row=0, column=1+i*2)
            entry.config(validate="key", validatecommand=(self.register(func=self.checkIPInput), "%P"))
            self.serverConfigWidget.append(entry)
            if i != len(self.IPTextVariableList)-1:
                Label(master=frame, text=".", font=self.FONT).grid(row=0, column=1+i*2+1)

    def createServerFrame(self, master:"Widget", row:"int", column:"int"):
        frame:"Frame" = self.createFrame(master=master, sticky=NSEW)
        Label(master=frame, text="Name: ", font=self.FONT).pack(side=LEFT)
        nameEntry:"Entry" = Entry(master=frame, textvariable=self.nameTextVariable, width=10, font=self.FONT, justify=RIGHT)
        nameEntry.pack(side=LEFT)
        self.serverConfigWidget.append(nameEntry)
        buttonWidth:"int" = max(len(ClientWindow.CONNECTION), len(ClientWindow.CONNECTING), len(ClientWindow.DISCONNECTION))
        self.connectButton:"Button" = Button(master=frame, text=ClientWindow.CONNECTION, width=buttonWidth, command=self.connection, font=self.FONT)
        self.connectButton.pack(side=RIGHT)
        self.createPortFrame(master=frame, side=RIGHT)
        self.createIPFrame(master=frame, side=RIGHT)

    def createShowTextFrame(self, master:"Widget", row:"int", column:"int"):
        frame:"Frame" = self.createFrame(master=master, row=row, column=column, sticky=NSEW)
        self.showText:"Text" = Text(master=frame, height=10, font=self.FONT, state=DISABLED)
        self.showText.grid(row=0, column=0, sticky=NSEW)
        scroll:"Scrollbar" = Scrollbar(master=frame, orient=VERTICAL, command=self.showText.yview)
        scroll.grid(row=0, column=1, sticky=NS)
        self.showText.config(yscrollcommand=scroll.set)

        self.showText.tag_config(tagName=ClientWindow.MSG_STATUT.SEND.name, foreground="#0000FF")
        self.showText.tag_config(tagName=ClientWindow.MSG_STATUT.RECV.name, foreground="#FF00FF")
        self.showText.tag_config(tagName=ClientWindow.MSG_STATUT.LOG_INFO.name, foreground="#00A038")
        self.showText.tag_config(tagName=ClientWindow.MSG_STATUT.LOG_ERROR.name, foreground="#FF0000")

        frame.grid_rowconfigure(index=0, weight=ClientWindow.WEIGHT)
        frame.grid_columnconfigure(index=0, weight=ClientWindow.WEIGHT)

    def sendMessage(self):
        if self.isAbleToSend():
            msgToSend:"str" = self.inputTextVariable.get()
            self.clientSocket.send_s(data=msgToSend)
            self.displayMsg(msg=">>{}".format(msgToSend), msgStatut=ClientWindow.MSG_STATUT.SEND)
            self.inputTextVariable.set(value="")

    def createInputTextFrame(self, master:"Widget", row:"int", column:"int"):
        frame:"Frame" = self.createFrame(master=master, row=row, column=column, sticky=NSEW)
        self.inputTextEntry:"Entry" = Entry(master=frame, textvariable=self.inputTextVariable, font=self.FONT)
        self.inputTextEntry.grid(row=0, column=0, sticky=NSEW)
        buttonText:"str" = "Send"
        self.sendButton:"Button" = Button(master=frame, text=buttonText, command=self.sendMessage, width=len(buttonText)+1, font=self.FONT, state=DISABLED)
        self.sendButton.grid(row=0, column=1, sticky=NSEW)
        self.inputTextEntry.bind(sequence="<Return>", func=lambda *paramList, **paramDict:self.sendButton.invoke())

        frame.grid_columnconfigure(index=0, weight=ClientWindow.WEIGHT)

    def createMessageFrame(self, master:"Widget", row:"int", column:"int"):
        frame:"Frame" = self.createFrame(master=master, row=row, column=column, sticky=NSEW)
        self.createShowTextFrame(master=frame, row=0, column=0)
        self.createInputTextFrame(master=frame, row=1, column=0)

        frame.grid_rowconfigure(index=0, weight=ClientWindow.WEIGHT)
        frame.grid_columnconfigure(index=0, weight=ClientWindow.WEIGHT)

    def getIP(self)->"str":
        return ".".join(textVariable.get() for textVariable in self.IPTextVariableList)
    def setIP(self, value:"str"):
        IPValueList:"list[str]" = value.split(sep=".")
        for i in range(len(IPValueList)):
            self.IPTextVariableList[i].set(value=IPValueList[i])
    def restoreDefaultIP(self):
        self.setIP(value=serverAddress[0])
    def restoreDefaultPort(self):
        self.portTextVariable.set(value=serverAddress[1])
    def restoreDefaultName(self):
        self.nameTextVariable.set(value="")
    def restoreDefaultData(self):
        self.restoreDefaultIP()
        self.restoreDefaultPort()
        self.restoreDefaultName()

    def restoreData(self):
        if isfile(path=ClientWindow.MEMORY_FILE_NAME):
            with open(file=ClientWindow.MEMORY_FILE_NAME, mode="r") as file:
                content:"str" = file.read()
            try:
                data:"dict[str,str]" = loads(s=content)
            except Exception as e:
                logger.error(msg=e)
                self.restoreDefaultData()
                return
            keySetDefaultList:"list[tuple[str,method(str),method()]]" = [
                (ClientWindow.IP, self.setIP, self.restoreDefaultIP),
                (ClientWindow.PORT, self.portTextVariable.set, self.restoreDefaultPort),
                (ClientWindow.NAME, self.nameTextVariable.set, self.restoreDefaultName)
            ]
            for jsonKey, setMethod, defaultMethod in keySetDefaultList:
                try:
                    value:"str" = data[ClientWindow.MEMORY_JSON_KEY[jsonKey]]
                    setMethod(value=value)
                except Exception as e:
                    logger.error(msg=e)
                    defaultMethod()
        else:
            self.restoreDefaultData()

    def saveData(self):
        data:"dict[str,str]" = {
            ClientWindow.MEMORY_JSON_KEY[ClientWindow.IP]: self.getIP(),
            ClientWindow.MEMORY_JSON_KEY[ClientWindow.PORT]: self.portTextVariable.get(),
            ClientWindow.MEMORY_JSON_KEY[ClientWindow.NAME]: self.nameTextVariable.get()
        }
        with open(file=ClientWindow.MEMORY_FILE_NAME, mode="w") as file:
            file.write(dumps(obj=data, indent=4, ensure_ascii=False))

    def destroy(self):
        if self.isConnected:
            self.disconnection()
        return super().destroy()


if __name__ == "__main__":
    try:
        window:"ClientWindow" = ClientWindow()
        window.mainloop()
        window.saveData()
    except Exception as e:
        logger.error(msg=e)