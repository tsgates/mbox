from ptrace.func_arg import FunctionArgument

class FunctionCallOptions(object):
    """
    Options to format a function call and its arguments.
    """
    def __init__(self,
    write_types=False, write_argname=False,
    replace_socketcall=True, string_max_length=300,
    write_address=False, max_array_count=20):
        self.write_address = write_address
        self.write_types = write_types
        self.write_argname = write_argname
        self.replace_socketcall = replace_socketcall
        self.string_max_length = string_max_length
        self.max_array_count = max_array_count
        self.instr_pointer = False

class FunctionCall(object):
    """
    A function call. Attributes:
     - name (str): function name
     - arguments: list of FunctionArgument objects
     - restype (str, optional): result type
     - resvalue (optional): result value
     - argument_class: class used to build the new arguments

    Methods:
     - format(): create a string representation of the call
     - addArgument(): add a new argument
     - clearArguments(): remove all arguments
    """
    def __init__(self, name, options, argument_class=FunctionArgument):
        self.name = name
        self.options = options
        self.arguments = []
        self.restype = None
        self.resvalue = None
        self.argument_class = argument_class

    def addArgument(self, value=None, name=None, type=None):
        arg = self.argument_class(self, len(self.arguments), self.options, value, type, name)
        self.arguments.append(arg)

    def clearArguments(self):
        self.arguments = []

    def __getitem__(self, key):
        if isinstance(key, str):
            for arg in self.arguments:
                if arg.name == key:
                    return arg
            raise KeyError("%r has no argument called %r" % (self, key))
        else:
            # Integer key
            return self.arguments[key]

    def format(self):
        arguments = [ arg.format() for arg in self.arguments ]
        arguments = ", ".join(arguments)
        if self.restype and self.options.write_types:
            return "%s %s(%s)" % (self.restype, self.name, arguments)
        else:
            return "%s(%s)" % (self.name, arguments)

    def __repr__(self):
        return "<FunctionCall name=%r>" % self.name

