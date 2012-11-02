from ptrace.error import PTRACE_ERRORS, writeError
from logging import getLogger
from ptrace.ctypes_tools import formatAddress

class FunctionArgument(object):
    """
    Description of a function argument. Attributes:
     - function: a Function objet
     - index (int): index of the argument (starting at zero)
     - options: a FunctionCallOptions objet
     - value (int)
     - type (str, optional)
     - text (str): string describing the argument

    Don't use text attribute directly, use getText() to format the
    argument instead.
    """
    def __init__(self, function, index, options,
    value=None, type=None, name=None):
        self.function = function
        self.index = index
        self.options = options
        self.value = value
        self.type = type
        self.name = name
        self.text = None

    def getText(self):
        if not self.text:
            try:
                text = self.createText()
                if text is not None:
                    self.text = str(text)
                elif self.type and self.type.endswith("*"):
                    self.text = formatAddress(self.value)
                else:
                    self.text = repr(self.value)
            except PTRACE_ERRORS, err:
                writeError(getLogger(), err,
                    "Format argument %s of function %s() value error"
                    % (self.name, self.function.name))
                self.text = repr(self.value)
        return self.text

    def format(self):
        text = self.getText()
        options = self.options
        if options.write_argname and self.name:
            if options.write_types and self.type:
                return "%s %s=%s" % (self.type, self.name, text)
            else:
                return "%s=%s" % (self.name, text)
        elif options.write_types and self.type:
            return "(%s)%s" % (self.type, text)
        else:
            return text

    def createText(self):
        return repr(self.value)

    def formatPointer(self, value, address):
        if self.options.write_address:
            return "%s at %s" % (value, formatAddress(address))
        else:
            return value

    def readStruct(self, address, struct):
        address = self.value

        struct_name = struct.__name__
        data = self.function.process.readStruct(address, struct)
        arguments = []
        for name, argtype in struct._fields_:
            value = getattr(data, name)
            try:
                text = self.formatStructValue(struct_name, name, value)
                if text is not None:
                    text = str(text)
                else:
                    text = repr(value)
            except PTRACE_ERRORS, err:
                writeError(getLogger(), err, "Format struct value error")
                text = repr(value)
            arguments.append("%s=%s" % (name, text))

        data = "<%s %s>" % (struct_name, ", ".join(arguments))
        return self.formatPointer(data, address)

    def formatStructValue(self, struct, name, value):
        return None

    def readArray(self, address, basetype, count):
        array = self.function.process.readArray(address, basetype, count)
        arguments = []
        for index in xrange(count):
            value = array[index]
            value = str(value)
            arguments.append(value)
        arguments = ", ".join(arguments)
        return self.formatPointer("<(%s)>" % arguments, address)

    def __repr__(self):
        return "argument %s of %s()" % (self.name, self.function.name)

