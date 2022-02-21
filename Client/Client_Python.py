from typing import Literal, Type, Callable
from laboratoryTools.network import serverAddress, Socket, ServerSocket, ClientSocket
from tkinter import Misc, Tk, StringVar, Frame, Button, Label, Entry, Text, Scrollbar # Classes used
from tkinter.font import Font
from tkinter import NORMAL, DISABLED    # Widget State Constants
from threading import Thread, currentThread
from select import select
from tkinter import INSERT, END # Index Constant for Text
from tkinter import NSEW, NS    # Fill Direction Size Constant
from tkinter import LEFT, RIGHT # Widget side display Constant
from tkinter import VERTICAL    # Scrollbar Direction Constant
from laboratoryTools.logging import logger, displayError
from os.path import isfile
from json import loads, dumps
from enum import Enum


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
        MEMORY_JSON_KEY[key] = "_".join(["MEMORY_JSON_KEY", key])

    MAX_PORT:"int" = 65535
    MAX_IP:"int" = 255

    WEIGHT:"int" = 1

    Side:"Type" = Literal['left', 'right', 'top', 'bottom']

    class MSG_STATUT(Enum):
        SEND = "#0000FF"
        RECV = "#FF00FF"
        LOG_INFO = "#00A038"
        LOG_ERROR = "#FF0000"

    def __init__(self):
        super().__init__()

        self.FONT:"Font" = Font(root=self, size=15)
        self.serverConfigEntry:"list[Entry]" = []
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
        return not self.isConnected and not False in map(lambda textVariable: textVariable.get() != "", textVariableList)
    def updateConnectionButtonState(self, *paramList, **paramDict):
        self.connectButton.config(state=NORMAL if self.isAbleToConnect() else DISABLED)

    def isAbleToSend(self)->"bool":
        return self.isConnected and self.inputTextVariable.get() != ""
    def updateSendButtonState(self, *paramList, **paramDict):
        self.sendButton.config(state=NORMAL if self.isAbleToSend() else DISABLED)

    def setTitle(self, info:"str"):
        self.title(string="{} - {}".format(ClientWindow.BASE_TITLE, info))

    @staticmethod
    def createFramePack(side:"Side", padx:"int"=None, *paramList, **paramDict)->"Frame":
        frame:"Frame" = Frame(*paramList, **paramDict)
        frame.pack(side=side)
        if padx is not None:
            frame.pack(padx=padx)
        return frame

    @staticmethod
    def createFrameGrid(row:"int", column:"int", sticky:"str"=None, *paramList, **paramDict)->"Frame":
        frame:"Frame" = Frame(*paramList, **paramDict)
        frame.grid(row=row, column=column)
        if sticky is not None:
            frame.grid(sticky=sticky)
        return frame

    def displayMsg(self, msg:"str", msgStatut:"MSG_STATUT"):
        startIndex:"str" = self.showText.index(index=INSERT)
        self.showText.config(state=NORMAL)
        self.showText.insert(index=END, chars="{}\n".format(msg))
        self.showText.config(state=DISABLED)
        self.showText.see(index=END)
        stopIndex:"str" = self.showText.index(index=INSERT)
        self.showText.tag_add(msgStatut.name, startIndex, stopIndex)
    def displaySendMsg(self, msg:"str"):
        self.displayMsg(msg=msg, msgStatut=ClientWindow.MSG_STATUT.SEND)
    def displayRecvMsg(self, msg:"str"):
        self.displayMsg(msg=msg, msgStatut=ClientWindow.MSG_STATUT.RECV)
    def displayInfoMsg(self, msg:"str"):
        self.displayMsg(msg=msg, msgStatut=ClientWindow.MSG_STATUT.LOG_INFO)
    def displayErrorMsg(self, msg:"str"):
        self.displayMsg(msg=msg, msgStatut=ClientWindow.MSG_STATUT.LOG_ERROR)

    def listenServerThreadRunMethod(self):
        while self.isConnected:
            socketList:"list[ClientSocket]" = select([self.clientSocket], [], [], ClientSocket.SELECT_TIMEOUT)[0]
            for socketWithMsg in socketList:
                try:
                    msgReceivedList:"list[str]" = socketWithMsg.recv_s(bufferSize=1024)
                    for msgReceived in msgReceivedList:
                        self.displayRecvMsg(msg="<<{}".format(msgReceived))
                        if msgReceived in (ServerSocket.STOP_SERVER, Socket.MSG_DISCONNECTION):
                            self.disconnection()
                except ConnectionResetError:
                    self.disconnection()

    def connectionThreadRunMethod(self):
        ip:"str" = self.getIP()
        port:"int" = int(self.portTextVariable.get())
        self.displayInfoMsg(msg="Connection to {}:{}...".format(ip, port))
        for widget in self.serverConfigEntry:
            widget.config(state="readonly")
        self.connectButton.config(text=ClientWindow.CONNECTING, state=DISABLED)
        self.setTitle(info=ClientWindow.CONNECTING)
        self.clientSocket:"ClientSocket" = ClientSocket(name=self.nameTextVariable.get())
        try:
            self.clientSocket.connect(address=(ip, port))
        except Exception as e:
            logger.error(msg=displayError(error=e))
            for widget in self.serverConfigEntry:
                widget.config(state=NORMAL)
            self.connectButton.config(text=ClientWindow.CONNECTION, state=NORMAL)
            self.setTitle(info=ClientWindow.DISCONNECTED)
            self.isConnected = False
            self.updateSendButtonState()
            
            self.displayErrorMsg(msg=displayError(error=e))
        else:
            self.connectButton.config(text=ClientWindow.DISCONNECTION, command=self.disconnection, state=NORMAL)
            self.setTitle(info=ClientWindow.CONNECTED)
            self.isConnected = True
            self.updateSendButtonState()
            self.listenServerThread:"Thread" = Thread(target=self.listenServerThreadRunMethod)
            self.listenServerThread.start()
            self.inputTextEntry.focus()
            self.displayInfoMsg(msg="Connected to {}.".format(self.clientSocket.name))

    def disconnection(self):
        logger.info(msg="Disconnection from {}".format(self.clientSocket))
        self.displayInfoMsg(msg="Disconnection from {}.".format(self.clientSocket.name))
        self.isConnected = False
        if currentThread() != self.listenServerThread:
            self.listenServerThread.join()
        self.clientSocket.close()

        self.setTitle(info=ClientWindow.DISCONNECTED)
        self.connectButton.config(text=ClientWindow.CONNECTION, command=self.connection)
        for widget in self.serverConfigEntry:
            widget.config(state=NORMAL)
        self.updateSendButtonState()

    def connection(self):
        thread:"Thread" = Thread(target=self.connectionThreadRunMethod)
        thread.start()

    # Callbacks to check inputs for PORT/IP entries
    @staticmethod
    def checkInputIsInt(input:"str", max:"int")->"bool":
        try:
            number:"int" = int(input)
            return number >= 0 and number <= max
        except Exception as e:
            logger.error(msg=displayError(error=e))
            return input == ""
    @staticmethod
    def checkPortInput(input:"str")->"bool":
        return ClientWindow.checkInputIsInt(input=input, max=ClientWindow.MAX_PORT)
    @staticmethod
    def checkIPInput(input:"str")->"bool":
        return ClientWindow.checkInputIsInt(input=input, max=ClientWindow.MAX_IP)

    def createPortFrame(self, master:"Misc", side:"Side"):
        frame:"Frame" = self.createFramePack(master=master, side=side, padx=50)
        Label(master=frame, text="PORT: ", font=self.FONT).grid(row=0, column=0)
        entry:"Entry" = Entry(master=frame, textvariable=self.portTextVariable, width=len(ClientWindow.MAX_PORT.__str__()), font=self.FONT, justify=RIGHT)
        entry.grid(row=0, column=1)
        entry.config(validate="key", validatecommand=(self.register(func=self.checkPortInput), "%P"))
        self.serverConfigEntry.append(entry)

    def createIPFrame(self, master:"Misc", side:"Side"):
        frame:"Frame" = self.createFramePack(master=master, side=side)
        Label(master=frame, text="IP: ", font=self.FONT).grid(row=0, column=0)
        width:"int" = len(ClientWindow.MAX_IP.__str__())
        for i in range(len(self.IPTextVariableList)):
            entry:"Entry" = Entry(master=frame, textvariable=self.IPTextVariableList[i], width=width, font=self.FONT, justify=RIGHT)
            entry.grid(row=0, column=1+i*2)
            entry.config(validate="key", validatecommand=(self.register(func=self.checkIPInput), "%P"))
            self.serverConfigEntry.append(entry)
            if i != len(self.IPTextVariableList)-1:
                Label(master=frame, text=".", font=self.FONT).grid(row=0, column=1+i*2+1)

    def createServerFrame(self, master:"Misc", row:"int", column:"int"):
        frame:"Frame" = self.createFrameGrid(master=master, row=row, column=column, sticky=NSEW)
        Label(master=frame, text="Name: ", font=self.FONT).pack(side=LEFT)
        nameEntry:"Entry" = Entry(master=frame, textvariable=self.nameTextVariable, width=10, font=self.FONT, justify=RIGHT)
        nameEntry.pack(side=LEFT)
        self.serverConfigEntry.append(nameEntry)
        buttonWidth:"int" = max(len(ClientWindow.CONNECTION), len(ClientWindow.CONNECTING), len(ClientWindow.DISCONNECTION))
        self.connectButton:"Button" = Button(master=frame, text=ClientWindow.CONNECTION, width=buttonWidth, command=self.connection, font=self.FONT)
        self.connectButton.pack(side=RIGHT)
        self.createPortFrame(master=frame, side=RIGHT)
        self.createIPFrame(master=frame, side=RIGHT)

    def createShowTextFrame(self, master:"Misc", row:"int", column:"int"):
        frame:"Frame" = self.createFrameGrid(master=master, row=row, column=column, sticky=NSEW)
        self.showText:"Text" = Text(master=frame, height=10, font=self.FONT, state=DISABLED)
        self.showText.grid(row=0, column=0, sticky=NSEW)
        scroll:"Scrollbar" = Scrollbar(master=frame, orient=VERTICAL, command=self.showText.yview)
        scroll.grid(row=0, column=1, sticky=NS)
        self.showText.config(yscrollcommand=scroll.set)

        for msgStatut in ClientWindow.MSG_STATUT:
            self.showText.tag_config(tagName=msgStatut.name, foreground=msgStatut.value)

        frame.grid_rowconfigure(index=0, weight=ClientWindow.WEIGHT)
        frame.grid_columnconfigure(index=0, weight=ClientWindow.WEIGHT)

    def sendMessage(self):
        if self.isAbleToSend():
            msgToSend:"str" = self.inputTextVariable.get()
            self.clientSocket.send_s(data=msgToSend)
            self.displaySendMsg(msg=">>{}".format(msgToSend))
            self.inputTextVariable.set(value="")

    def createInputTextFrame(self, master:"Misc", row:"int", column:"int"):
        frame:"Frame" = self.createFrameGrid(master=master, row=row, column=column, sticky=NSEW)
        self.inputTextEntry:"Entry" = Entry(master=frame, textvariable=self.inputTextVariable, font=self.FONT)
        self.inputTextEntry.grid(row=0, column=0, sticky=NSEW)
        buttonText:"str" = "Send"
        self.sendButton:"Button" = Button(master=frame, text=buttonText, command=self.sendMessage, width=len(buttonText)+1, font=self.FONT, state=DISABLED)
        self.sendButton.grid(row=0, column=1, sticky=NSEW)
        self.inputTextEntry.bind(sequence="<Return>", func=lambda *paramList, **paramDict:self.sendButton.invoke())

        frame.grid_columnconfigure(index=0, weight=ClientWindow.WEIGHT)

    def createMessageFrame(self, master:"Misc", row:"int", column:"int"):
        frame:"Frame" = self.createFrameGrid(master=master, row=row, column=column, sticky=NSEW)
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
        self.portTextVariable.set(value=serverAddress[1].__str__())
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
                logger.error(msg=displayError(error=e))
                self.restoreDefaultData()
                return
            keySetDefaultList:"list[tuple[str, Callable[[str],None], Callable[[],None]]]" = [
                (ClientWindow.IP, self.setIP, self.restoreDefaultIP),
                (ClientWindow.PORT, self.portTextVariable.set, self.restoreDefaultPort),
                (ClientWindow.NAME, self.nameTextVariable.set, self.restoreDefaultName)
            ]
            for jsonKey, setMethod, defaultMethod in keySetDefaultList:
                try:
                    value:"str" = data[ClientWindow.MEMORY_JSON_KEY[jsonKey]]
                    setMethod(value=value)  # Ignore annotation error because parameter name specification is unable.
                except Exception as e:
                    logger.error(msg=displayError(error=e))
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
        logger.error(msg=displayError(error=e))