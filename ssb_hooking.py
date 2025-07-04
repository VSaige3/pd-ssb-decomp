# TODO: link names to function decompilation
# TODO: elegantly show line numbers
# TODO: add a jump stack (space progresses, backspace regresses) !!!
# TODO: make hooks work lmao
# TODO: make right clicks also right click

import os   # for join
import struct
import sys
import io
import json

from functools import partial

import tkinter as tk
from tkinter import ttk 
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import *
import tkinter.filedialog
import tkinter.simpledialog
from tkinter import messagebox


from ssb_file import *

mod_fileroot = os.path.join(os.environ.get('LOCALAPPDATA'), 'Packages\\Microsoft.MSEsper_8wekyb3d8bbwe\\RoamingState\\mods')

def set_text_selection(textwidget, start, end, tag='sel'):
    # remove old tag
    textwidget.tag_remove(tag, '1.0', 'end')
    textwidget.tag_add(tag, start, end)
    # TODO: make it work if they haven't selected anything


# def _setup_dialog(w):
#     if w._windowingsystem == "aqua":
#         w.tk.call("::tk::unsupported::MacWindowStyle", "style",
#                   w, "moveableModal", "")
#     elif w._windowingsystem == "x11":
#         w.wm_attributes("-type", "window")

def is_valid_hex(self, newtxt: str):
    return all([c in '123456789abcdef' for c in newtxt.lower()])


class HookingFrame(ttk.Frame):
    class HookDialog(tk.simpledialog.Dialog):
        def __init__(self, parent, hookoptions, title='Add Hook'):
            # these are a subset of the properties of a hook
            hoption_list = ['original_offset', 'original_command', 'hook_length', 'hook_offset',
                            'hook_type', 'num_args', 'description']
            # map each to its value or null
            self.hookoptions = {option: tk.StringVar(master=parent, value=hookoptions.get(option, 0)) for option in hoption_list}
            self.result = None
            super().__init__(parent=parent, title=title)

        # def go(self):
        #     pass

        def body(self, master):
            dbody = ttk.Frame(master)
            dbody.pack(fill='both')

            self.entry_dict = dict()

            row = 0
            for option in self.hookoptions:
                lbl = ttk.Label(dbody, text=' '.join(option.split('_')).title())
                lbl.grid(row=row, column=0)
                entry = ttk.Entry(dbody, textvariable=self.hookoptions[option])

                # if self.hookoptions[option] is not None:
                #     def_value = self.hookoptions[option]
                #     if isinstance(def_value, int):
                #         entry.insert('end', '{:08X}'.format(def_value))
                #     else:
                #         entry.insert('end', def_value)

                entry.grid(row=row, column=1)

                self.entry_dict[option] = entry
                row += 1

            return dbody

        def validate(self):
            try:
                # TODO: this should be able to handle non-hex
                original_offset = int(self.entry_dict['original_offset'].get(), base=16)
                original_command = int(self.entry_dict['original_command'].get(), base=16)
                hook_length = int(self.entry_dict['hook_length'].get(), base=16)
                hook_offset = int(self.entry_dict['hook_offset'].get(), base=16)
                hook_type = HookType.FUNCTION
                num_args = int(self.entry_dict['hook_offset'].get(), base=10)
                description = self.entry_dict['description'].get()
                self.result = Hooking(
                    original_offset=original_offset,
                    original_command=original_command,
                    hook_length=hook_length,
                    hook_offset=hook_offset,
                    hook_type=hook_type,
                    num_args=num_args,
                    description=description
                )
                return True
            except ValueError:
                print('uh oh')  # replace with real error msg
                return False
    
    class LocalEditDialog(tk.simpledialog.Dialog):
        def __init__(self, parent, indx, do_full_func=False):
            super().__init__(parent, "Edit Local Names")
            self.indx = indx
            self.do_full_func = do_full_func
            self.parent = parent

            # calculate bounds
            self.fl: SSBFile = parent.ssb_file
            if do_full_func:
                start, end = self.fl.get_function_bounds(indx)
            else:
                start = indx
                end = indx + 1
            
            # collect symbols in this range
            self.symbols = []
            for i in range(start, end):
                if i in self.fl.var_symbols:
                    self.symbols.extend(self.fl.var_symbols[i])
        
        def body(self, master):
            dbody = ttk.Frame(master)
            dbody.pack(fill='both')

            start_index_l = []
            stack_pos_l = []
            symbol_dat_l = []

            for symb in self.symbols:
                frm = ttk.Frame(self)
                frm.pack(side='top')
                start_index_v = tk.StringVar(value=hex(symb.start_index))
                start_index_v = tk.StringVar(value=hex(symb.start_index))
                start_index_v = tk.StringVar(value=hex(symb.start_index))
                ttk.Entry(frm, validate='key', validatecommand=self.parent.hexvalidate, textvariable=start_index_v)


    class BodySearchDialog(tk.simpledialog.Dialog):
        def __init__(self, parent, title=None, orig_text=''):
            self.result = None
            self.orig_text = orig_text
            if title is None:
                title = 'Search Body'
            super().__init__(parent, title)

        def body(self, master):
            dbody = ttk.Frame(master)
            dbody.pack(fill='both')
            # add search box
            self.searchbox = ttk.Entry(dbody)
            self.searchbox.pack(side='top', fill='both')
            self.searchbox.insert('end', self.orig_text)
            # same opcode checkbox
            self.only_match_opcode = tk.IntVar()
            self.same_opcode_checkbox = ttk.Checkbutton(dbody, text='Only Match Opcode', variable=self.only_match_opcode)
            self.same_opcode_checkbox.pack(side='left', fill='both')
            return dbody

        def validate(self):
            # uhh eventually we'll add more here but
            try:
                search = int(self.searchbox.get(), base=16)
                only_match_opcode = bool(self.only_match_opcode.get())
                self.result = {'search': search, 'only_match_opcode': only_match_opcode}
                return True
            except ValueError:
                return False

    class BodyJumpPanel(tk.Toplevel):     # to be added to toplevel
        def __init__(self, hookframe, jumpindices, title=None):
            master = hookframe.winfo_toplevel()
            tk.Toplevel.__init__(self, master)

            self.wm_withdraw()
            self.jumpindices = jumpindices

            if title:
                self.title(title)
            else:
                self.title('Body Jump Panel')

            self.needs_scrollbar = True

            # _setup_dialog(self)

            self.parent = hookframe

            self.result = None

            body = Frame(self)
            self.initial_focus = self.body(body)
            body.pack(padx=5, pady=5)

            minwidth = self.winfo_reqwidth()
            minheight = self.winfo_reqheight()
            width = max(minwidth, 300)
            height = min(minheight, 500)
            self.geometry('{}x{}'.format(width, height))

            # wait for window to appear on screen before calling grab_set
            self.wm_deiconify()
            self.wait_visibility()
            # self.grab_set()
            self.wait_window(self)

        def body(self, master):

            self.scrollbar = Scrollbar(master)
            self.scrollbar.pack(side='right', fill='y')
            self.listvar = tk.StringVar()
            self.jumplist = tk.Listbox(master, listvariable=self.listvar, yscrollcommand=self.scrollbar.set)
            self.jumplist.pack(padx=10, pady=10)
            self.jumplist.bind('<<ListboxSelect>>', self.do_jump_event)

            self.scrollbar.config(command=self.jumplist.yview)

            self.update_jump_list()
            return self.jumplist

        def update_jump_list(self):
            l = ['{:08x}'.format(jumpindex) for jumpindex in self.jumpindices]
            self.listvar.set(value=l)

        def do_jump_event(self, event):
            currsel = self.jumplist.curselection()
            if len(currsel) > 0:
                self.parent.decomp_or_select(self.jumpindices[currsel[0]])


    def __init__(self, root):
        super().__init__(root, padding=10)

        # init stuff
        self.hook_dict = None
        self.ssb_file_name = None

        # register the hex validate
        self.hexvalidate = (self.register(is_valid_hex), '%P')

        # colors and shit
        root.config(bg='black')

        # menu bar
        menubar = tk.Menu(root)

        # save/load menu options
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label='Load Hooks', command=self.load_hooking_file)
        filemenu.add_command(label='Save Hooks', command=self.save_hooking_file)
        filemenu.add_command(label='Save Changes to File', command=self.save_to_file)
        filemenu.add_command(label='Add SSB File', command=self.add_ssb_to_hooks)
        filemenu.add_command(label='Close', command=root.destroy)
        menubar.add_cascade(label='File', menu=filemenu)
        # edit menu options
        editmenu = tk.Menu(menubar, tearoff=0)
        truncmenu = tk.Menu(editmenu, tearoff=0)
        truncmenu.add_command(label='Body', command=self.create_body_trunc_dialog)
        truncmenu.add_command(label='Function Table', command=self.create_ftable_trunc_dialog)
        truncmenu.add_command(label='Strings', command=self.create_strings_trunc_dialog)
        editmenu.add_cascade(label='Change Size', menu=truncmenu)
        menubar.add_cascade(label='Edit', menu=editmenu)
        root.config(menu=menubar)

        # files display
        self.ssbfile_combo = tk.ttk.Combobox(self, state='readonly', values=[])
        self.ssbfile_combo.bind('<<ComboboxSelected>>', self.ssbfile_selected)
        self.ssbfile_combo.grid(column=0, row=0)

        # tabbed panel
        self.tabControl = tk.ttk.Notebook(self)
        self.tabHeader = tk.ttk.Frame(self.tabControl)
        self.tabControl.add(self.tabHeader, text='Header', underline=0)
        self.tabBody = tk.ttk.Frame(self.tabControl)
        self.tabControl.add(self.tabBody, text='Body', underline=0)
        self.tabFTable = tk.ttk.Frame(self.tabControl)
        self.tabControl.add(self.tabFTable, text='Function Table', underline=0)
        self.tabStrings = tk.ttk.Frame(self.tabControl)
        self.tabControl.add(self.tabStrings, text='Strings', underline=0)
        self.tabControl.grid(column=0, row=1)

        self.make_tabs()

        self.bind_all('<Alt-Left>', lambda _: self.unjump())
        self.bind_all('<Alt-Right>', lambda _: self.rejump())
        root.protocol("WM_DELETE_WINDOW", lambda: self.on_closing(root))

        # create tag formats
        self.tabBodyRawText.tag_configure('highlight', background='lightblue')
        self.tabBodyDecompText.tag_configure('highlight', background='lightblue')
        self.tabBodyDecompText.tag_configure('func-title', font='TkTextFont 13 bold', underline=True)

        self.decomp_start_index = None
        self.decomp_end_index = None

        self.jump_stack = []

        self.make_popups()

        # hooks display
        self.hook_frame = ttk.Frame(self, height=500)
        self.hook_frame.grid(column=1, row=2)

        self.hook_frame_scrollbar = tk.Scrollbar(self.hook_frame)
        self.hook_frame_scrollbar.pack(side='right', fill='both')

        self.scrollable_gridded_frame = tk.Frame(self.hook_frame, height=800)
        self.scrollable_gridded_frame.pack(side='right', fill='both')
        self.grid_table_header()
        
        self.default_scroll_text = ttk.Label(self.scrollable_gridded_frame, text='No File Selected')
        self.default_scroll_text.grid(column=0, row=1, columnspan=3)

        # add hook / remove hook
        self.hook_add_btn = tk.ttk.Button(self, text='Add Hook', command=self.request_add_hook, state='disabled')
        self.hook_add_btn.grid(column=1, row=0)

        # function heads-up
        self.function_brief = tk.ttk.Label(self, text='No Function selected')
        self.function_brief.grid(column=1, row=1)

        # load default hooks
        self.loaded_fnames = []
        self.hook_dict = dict()
        try: 
            f = open('./hooks.json', mode='r')
            if f is not None:
                self.hook_dict = json_to_hooks(json.load(f))
                f.close()
                self.update_file_combo()
        except IOError:
            print('FAILED TO LOAD HOOKS, ASSUMING NO HOOKS')
        self.symbols = dict()
        try:
            f = open('./symbols.json', mode='r')
            if f is not None:
                self.symbols = json.load(f)
                f.close()
        except IOError:
            print('FAILED TO LOAD SYMBOLS')
        

    def make_tabs(self):
        # header tab
        self.tabHeaderRawText = ScrolledText(self.tabHeader, width=32, wrap='none')
        self.tabHeaderRawText.pack(side='left', fill='both')
        self.tabHeaderRawText.insert('1.0', 'No input file selected')   # placeholder text

        # data tab
        self.tabBodyRawText = ScrolledText(self.tabBody, width=46, wrap='none')
        self.tabBodyDecompText = ScrolledText(self.tabBody, width=32, wrap='none')
        self.tabBodyRawText.pack(side='left', fill='y')
        self.tabBodyDecompText.pack(side='right', fill='y')
        self.tabBodyRawText.insert('1.0', 'No input file selected')
        self.tabBodyDecompText.insert('1.0', 'No data to decompile')

        # function table tab
        self.tabFTableRawText = ScrolledText(self.tabFTable, width=32, wrap='none')
        self.tabFTableFText = ScrolledText(self.tabFTable, width=32, wrap='none')   # DO NOT USE
        self.tabFTableRawText.pack(side='left', fill='y')
        # self.tabFTableFText.pack(side='right', fill='y')
        self.tabFTableRawText.insert('1.0', 'No input file selected')
        # self.tabFTableFText.insert('1.0', 'No data to format')

        # strings tab
        self.strings_hscroll = Scrollbar(self.tabStrings, orient='horizontal')

        self.tabStringsText = ScrolledText(self.tabStrings, width=50, wrap='none', xscrollcommand=self.strings_hscroll.set)
        self.strings_hscroll.pack(side='bottom', fill='x')
        self.strings_hscroll.config(command=self.tabStringsText.xview)
        self.tabStringsText.pack()
        self.tabStringsText.insert('1.0', 'No input file selected')
        # add horisontal scroll

        self.disable_text_widgets()

    def make_popups(self):
        self.bodyRawPopup = tk.Menu(root, tearoff=False)
        self.bodyRawPopup.add_command(label='Create hook', command=self.body_make_hook)
        self.bodyRawPopup.add_command(label='Search for similar', command=self.body_search_similar)
        self.bodyRawPopup.add_command(label='Do jump', command=self.body_do_jump)
        self.bodyRawPopup.add_command(label='Go back', command=self.unjump)
        self.bodyRawPopup.add_command(label='Find jumps to', command=self.body_map_refs)
        self.bodyRawPopup.add_command(label='Go to string', command=self.go_to_string)
        self.bodyRawPopup.add_command(label='Change to...', command=self.body_raw_edit)
        self.bodyRawPopup.add_command(label='Insert nops after', command=self.body_insert_nops)
        self.bodyRawPopup.add_command(label='Edit locals here', command=self.edit_locals_at_pos)

        self.FTableRawPopup = tk.Menu(root, tearoff=False)
        self.FTableRawPopup.add_command(label='Go to function', command=self.ftable_goto_def)
        self.FTableRawPopup.add_command(label='Add hook at function', command=self.ftable_make_hook)
        self.FTableRawPopup.add_command(label='Go back', command=self.unjump)
        self.FTableRawPopup.add_command(label='Change to...', command=self.ftable_edit)
        self.FTableRawPopup.add_command(label='Insert new after', command=self.ftable_insert_after)

        self.stringsPopup = tk.Menu(root, tearoff=False)
        self.stringsPopup.add_command(label='Find references', command=self.strings_map_refs)
        self.stringsPopup.add_command(label='Go back', command=self.unjump)
        self.stringsPopup.add_command(label='Change to...', command=self.strings_edit)

        self.ftitlePopup = tk.Menu(root, tearoff=False)
        self.ftitlePopup.add_command(label='Rename Function', command=self.ftitle_rename_func)

    def push_jump(self, jump):
        self.jump_stack.append(jump)
        if len(self.jump_stack) > 100:
            self.jump_stack.pop(0)

    def pop_jump(self):
        if len(self.jump_stack) > 0:
            jmp = self.jump_stack.pop()
            self.jump_stack.insert(0, jmp)
            return jmp
        else:
            return None

    ### MENU ITEMS
    ## (remember selected_index)
    # body
    def body_make_hook(self):
        hex_format = '{:X}'
        offset = self.selected_index * 4 + 0x20     # to offset, add header
        command = self.ssb_file.data[self.selected_index]
        hook = self.ask_make_hook(
            original_offset=hex_format.format(offset),
            original_command=hex_format.format(command),
            hook_offset=self.get_last_unallocated_offset()
        )
        if hook is not None:
            self.hook_dict[self.ssb_file_name].append(hook)
            self.update_hook_list()
        # TODO: resize body section

    def body_search_similar(self):
        self.create_body_search_dialog(orig_text='{:08X}'.format(self.ssb_file.data[self.selected_index]))

    def body_decompile(self):
        func = self.get_function(self.selected_index)
        if func:
            self.create_decomp_text(func)
            self.mark_body_decomp_tags_by_index(self.selected_index)
        else:
            print('could not find function')

    def generic_select(self, dest_indx, dest_tab):
        self.tabControl.select(dest_tab)
        if dest_tab == 0:
            # it won't be
            pass
        elif dest_tab == 1:
            self.decomp_or_select(dest_indx)
        elif dest_tab == 2:
            tagname = 'functable-f-{}'.format(dest_indx)
            start, end = self.tabFTableRawText.tag_ranges(tagname)
            set_text_selection(self.tabFTableRawText, start, end)
            self.tabFTableRawText.see(start)
        elif dest_tab == 3:
            tagname = 'string-f-{}'.format(dest_indx)
            start, end = self.tabStringsText.tag_ranges(tagname)
            set_text_selection(self.tabStringsText, start, end)
            self.tabStringsText.see(start)

    def unjump(self):
        dest = self.pop_jump()
        if dest is not None:
            dest_indx, dest_tab = dest
            self.generic_select(dest_indx, dest_tab)

    def rejump(self):
        dest = self.jump_stack.pop(0)
        if dest is not None:
            self.jump_stack.append(dest)
            dest_indx, dest_tab = dest
            self.generic_select(dest_indx, dest_tab)


    def body_do_jump(self):
        cmd = self.ssb_file.data[self.selected_index]
        jmp_offset = get_jump_offset(cmd)
        if jmp_offset is not None:
            dest_index = self.selected_index + jmp_offset
        else:
            print('not a jump')
            return
        self.push_jump((self.selected_index, 1))
        self.decomp_or_select(dest_index)

    def go_to_string(self):
        cmd = self.ssb_file.data[self.selected_index]
        opcode = cmd & 0xff
        if opcode == 0x11:
            dest_indx = to_signed_16(cmd >> 0x10)
        else:
            print('Not a string ptr')
            return
        self.push_jump((self.selected_index, 1))
        # print(hex(dest_indx))
        self.generic_select(dest_indx, 3)

    def body_raw_edit(self):
        cmd = self.ssb_file.data[self.selected_index]
        newval = tk.simpledialog.askstring('Edit', 'New text: ', initialvalue='{:08X}'.format(cmd))
        try:
            i = int(newval, base=16)
            # print(i)
            if i > 0xFFFFFFFF:
                print('Too large')
            else:
                self.ssb_file.data[self.selected_index] = i
                self.reload_display()
                self.body_decompile()
                self.decomp_or_select(self.selected_index)
        except ValueError:
            print('Failed to parse')

    def body_insert_nops(self):
        ins_size = tk.simpledialog.askinteger('Insert Nops', 'Num instructions: ', initialvalue=1)
        if ins_size > 0:
            self.ssb_file.insert_instrs(ins_size, self.selected_index)
            self.reload_display()
            self.body_decompile()
            self.decomp_or_select(self.selected_index)
    
    def edit_locals_at_pos(self):
        # HookingFrame.LocalEditDialog(self, self.selected_index, False)
        stack_pos = tk.simpledialog.askinteger('Select Index', 'Index on Stack:', initialvalue=-1)
        # for vs in self.ssb_file.sy
        # TODO: check if this overwrites something
        varname = tk.simpledialog.askstring('Var Name', 'Var Name')
        proceed = messagebox.askokcancel('Proceed?', 'This may shadow other variable names, proceed?')
        if proceed:
            indx = self.selected_index
            self.ssb_file.var_symbols.setdefault(indx, []).append(SSBDecompiler.VarSymbol(indx, stack_pos, {"name": varname}))
            self.ssb_file.update_raw()
            self.push_lvars_to_symbols(self.ssb_file_name)
            s_indx = self.selected_index
            self.selected_index = None
            self.reload_display()
            self.decomp_or_select(s_indx)

    def body_map_refs(self):
        found_indices = []
        for i in range(len(self.ssb_file.data)):
            cmd = self.ssb_file.data[i]
            if cmd & 0xff in (0x07, 0x03, 0x08):
                dest = i + to_signed_16(cmd >> 0x10) + 1
                if dest == self.selected_index:
                    found_indices.append(i)
        HookingFrame.BodyJumpPanel(self, found_indices)
        # display in a nice dialog

    # ftable
    def ftable_goto_def(self):
        self.push_jump((self.selected_index, 2))
        self.selected_index = self.ssb_file.functable[self.selected_index][0]
        tagname = 'data-raw-{}'.format(self.selected_index)
        self.tabControl.select(1)
        self.body_decompile()

    def ftable_make_hook(self):
        pass

    def ftable_edit(self):
        old = self.ssb_file.functable[self.selected_index]
        newtxt = tk.simpledialog.askstring('Edit', 'New text: ', initialvalue=self.selected_index)
        if not newtxt or len(newtxt) > 12:
            print('too long')
        else:
            self.ssb_file.functable.pop(self.selected_index)
            self.selected_index = newtxt
        self.focus_force()
        while not self.focus_get():
            pass
        newdest_str = tk.simpledialog.askstring('Edit', 'New dest: ', initialvalue='{:08X}'.format(old[0]))
        if newdest_str:
            newdest = int(newdest_str, base=16)
            if newdest > 0xFFFFFFFF:
                print('too big')
            else:
                old = (newdest, old[1], old[2])
        self.ssb_file.functable.add(self.selected_index, old)
        self.reload_display()


    def ftable_insert_after(self):
        pass


    # strings
    def strings_map_refs(self):
        # we're looking for
        search = (self.selected_index << 0x10) + 0x11
        # self.tabControl.select(1)
        self.create_body_search_dialog(orig_text='{:08x}'.format(search), title='String Search')

    def strings_edit(self):
        pass

    def ftitle_rename_func(self):
        func: SSBFunc = self.get_function(self.selected_index)
        # if its supplied by the ssb I won't allow changes
        start_index = func.bounds[0]
        oldname = self.function_map[start_index].name
        if oldname in self.ssb_file.functable:
            print('can\'t rename mapped function')
            return
        
        newname = tk.simpledialog.askstring('Rename', 'Enter New Name:', initialvalue=oldname)
        if newname == '' or newname is None:
            return
        # find in the list of loaded functions
        for loaded_func in self.loaded_fnames:
            if loaded_func['start_index'] == start_index:
                oldname = loaded_func['data']['name']
                messagebox.askokcancel('Proceed?', 'This will overwrite function\'s former name: {}'.format(oldname))
                loaded_func['data']['name'] = newname
                self.process_functions()
                self.reload_display()
                self.decomp_or_select(self.selected_index)
                return
        
        self.loaded_fnames.append({'start_index': start_index, 'data': {'name': newname}})
        self.process_functions()
        self.reload_display()
        self.decomp_or_select(self.selected_index)
        

    def process_functions(self):
        self.function_map = dict()

        def recursive_add_functions(parent: SSBFunc):
            for i in range(*parent.bounds):
                cmd = self.ssb_file.data[i]
                if cmd & 0xff == 0x03:    # func call
                    dest = to_signed_16(cmd >> 0x10) + i
                    # prevent duplicates (really lazy)
                    if dest not in self.function_map:
                        fileoffset = dest * 4 + 0x20
                        temp = SSBFunc()
                        if dest * 4 >= self.ssb_file.header.functable_offset:
                            # out of bounds
                            temp.name = f"unresolved_func_0x{fileoffset:X}"
                            temp.bounds = (0, 0)    # TODO: idk fix this
                        else:
                            temp.name = f"func_0x{fileoffset:X}"
                            temp.bounds = self.ssb_file.get_function_bounds(dest)
                            self.function_map.update({dest: temp})
                            recursive_add_functions(temp)
                        temp.numparams = cmd >> 0x08 & 0xff
                        temp.returns = (dest < len(self.ssb_file.data) - 1 and
                                        self.ssb_file.data[dest + 1] & 0xff == 0x10)
        print(f'AT START: \n{self.loaded_fnames}')
        # first, process each named function
        for name in self.ssb_file.functable:
            f = self.ssb_file.functable[name]
            # change numparams and returns if necceccary
            if f[0] >= len(self.ssb_file.data):
                bounds = (f[0], f[0])   # TODO: idk
            else:
                bounds = (f[0], self.ssb_file.get_function_end(f[0]))
            numparams = self.ssb_file.autocalc_params(f[0])
            temp = SSBFunc(name=name, bounds=bounds, numparams=numparams, returns=False)
            self.function_map.update({f[0]: temp})
            recursive_add_functions(temp)
        print(f'AT END: \n{self.loaded_fnames}')
        # now, map every named one from symbols
        for entry in self.loaded_fnames:
            print(entry)
            start_index = entry['start_index']
            bounds = (start_index, self.ssb_file.get_function_end(start_index))
            data = entry.setdefault('data', dict())
            numparams = data.get('numparams', self.ssb_file.autocalc_params(f[0]))
            returns = data.get('returns', False)
            name = data.get('name', f"unused_func_0x{to_offset(start_index):X}")
            temp = SSBFunc(name=name, bounds=bounds, numparams=numparams, returns=returns)
            self.function_map.update({start_index: temp})
            recursive_add_functions(temp)

        # first section may be a "data" section made up of non-commands and nops
        data_end = 0
        command_streak = 0
        min_command_streak = 4
        has_data = False
        # if the first 4 commands are valid instructions, skip
        # TODO: this is stupid and silly
        if len(self.ssb_file.data) >= min_command_streak:
            for i in range(min_command_streak):
                c = self.ssb_file.data[data_end]
                opcode = c & 0xff
                if not (opcode <= 0x1f):
                    has_data = True
                    break
            if has_data:
                data_f = SSBFunc("$DATA")
                while data_end < len(self.ssb_file.data):
                    c = self.ssb_file.data[data_end]
                    opcode = c & 0xff
                    if opcode <= 0x1f and opcode != 0x00:
                        command_streak -= 1
                    else:
                        command_streak = 0
                    if command_streak == min_command_streak:
                        data_end -= min_command_streak
                        data_f.bounds = (0, data_end)
                    data_end += 1
                self.function_map.update({0: data_f})
                print(f"$data has len {data_end}")
            else:
                print("No data")

        # map unused functions
        # print(self.function_map)
        pos = 0
        while pos < len(self.ssb_file.data) - 1:
            if pos not in self.function_map:
                # get end
                bounds = self.ssb_file.get_function_bounds(pos)
                offset = to_offset(pos)
                temp = SSBFunc(name=f"unused_func_0x{offset:X}",
                               bounds=bounds,
                               numparams=self.ssb_file.autocalc_params(pos))
                self.function_map.update({pos: temp})
                pos = bounds[1] + 1
            else:
                temp = self.function_map.get(pos)
                if temp is None or temp.bounds[0] >= temp.bounds[1]:
                    pos += 1
                else:
                    pos = temp.bounds[1] + 1
        for entry in self.function_map:
            f = self.function_map[entry]

    def get_function(self, indx):
        if indx < 0:
            # idk do something
            return None
        if indx > len(self.ssb_file.data):
            # idk do something
            return None
        while indx > 0:
            if indx in self.function_map:
                return self.function_map[indx]
            indx -= 1
        return self.function_map[0]

    def create_decomp_text(self, func):
        start, end = func.bounds
        tokens = SSBDecompiler.tokenize(self.ssb_file.data, start, end)
        self.enable_text_widgets()
        # clear
        self.tabBodyDecompText.delete('0.0', 'end')
        self.tabBodyDecompText.insert('end', func.name, "func-title")
        self.tabBodyDecompText.insert('end', '\n')
        self.tabBodyDecompText.tag_bind('func-title', '<Button>', self.do_decomp_func_name_action)
        lvars = []
        for token in tokens:
            indx = token[-1]
            tagname = 'decomp-text-{}'.format(indx)
            if indx in self.ssb_file.var_symbols:
                lvars.extend(self.ssb_file.var_symbols[indx])
            self.tabBodyDecompText.insert('end', SSBDecompiler.str_token(token, lvars, lambda indx: self.get_function(indx)), tagname)
            self.tabBodyDecompText.insert('end', '\n')
            self.tabBodyDecompText.tag_bind(tagname, '<Button>', partial(self.do_body_raw_action, index=token[-1]))
        self.disable_text_widgets()

        self.decomp_start_index = start
        self.decomp_end_index = end

    def mark_body_decomp_tags_by_index(self, i, event=None):
        decomp_tagname = 'decomp-text-{}'.format(i)
        body_tagname = 'data-raw-{}'.format(i)

        if decomp_tagname not in self.tabBodyDecompText.tag_names():
            # prolly 0x0f (should instead mark the decomp with both tags)
            decomp_tagname = 'decomp-text-{}'.format(i - 1)

        self.mark_decomp_tag(decomp_tagname)
        self.mark_body_tag(body_tagname)

    def mark_decomp_tag(self, decomp_tagname):
        _range = self.tabBodyDecompText.tag_ranges(decomp_tagname)
        if len(_range) == 0:
            return
        start, end = _range
        set_text_selection(self.tabBodyDecompText, start, end, tag='highlight')
        self.tabBodyDecompText.see(start)

    def mark_body_tag(self, body_tagname):
        start, end = self.tabBodyRawText.tag_ranges(body_tagname)
        set_text_selection(self.tabBodyRawText, start, end, tag='highlight')
        self.tabBodyRawText.see(start)

    def ask_make_hook(self, **hookoptions):
        df = HookingFrame.HookDialog(self, hookoptions=hookoptions)
        return df.result

    def create_body_search_dialog(self, orig_text=None, title=None):
        df = HookingFrame.BodySearchDialog(self, orig_text=orig_text, title=title)
        if df.result is not None:
            search = df.result['search']
            only_match_opcode = df.result['only_match_opcode']
            # do search (should prolly pull up a new dialog)
            self.tabControl.select(1)
            # search the file data cuz its faster
            foundindices = []
            for i in range(len(self.ssb_file.data)):
                if only_match_opcode:
                    if (self.ssb_file.data[i] - search) & 0xff == 0:
                        foundindices.append(i)
                else:
                    if self.ssb_file.data[i] == search:
                        foundindices.append(i)
            print(foundindices)
            print([hex(self.ssb_file.data[x]) for x in foundindices])
            if only_match_opcode:
                title = 'Opcode {:02x}'.format(search & 0xff)
            else:
                title = '{:08x}'.format(search)
            HookingFrame.BodyJumpPanel(self, foundindices, title=title)

    def create_body_trunc_dialog(self):
        print('oooh resizing body')
        #TODO: make hex numbers work
        if self.ssb_file is None:
            return
        oldsize = len(self.ssb_file.data)
        prompt = f'current body size is {oldsize}(dec).\nNew body size (dec):'
        newsize = tk.simpledialog.askinteger(title='', prompt=prompt, initialvalue=oldsize)
        if newsize < oldsize:
            text = 'This will delete data, continue?'
            confirm = tk.simpledialog.SimpleDialog(self, text, buttons=['Yes', 'No']).go()
            if confirm == 1:
                return
        if newsize < 0:
            text = 'Negative number interpreted as 0, continue?'
            confirm = tk.simpledialog.SimpleDialog(self, text, buttons=['Yes', 'No']).go()
            if confirm == 1:
                return
            newsize = 0

        deltasize = newsize - oldsize

        # have to modify the underlying buffer
        if deltasize > 0:
            for _ in range(deltasize):
                # self.ssb_file_buffer.insert(self.ssb_file.header.functable_offset, 00)
                self.ssb_file.data.insert(-1, 00)
        else:
            for i in range(deltasize):
                # self.ssb_file_buffer.pop(self.ssb_file.header.functable_offset - 1 - i)
                self.ssb_file.data.pop()

        self.ssb_file.header.strings_offset += deltasize
        self.ssb_file.header.functable_offset += deltasize

        self.ssb_file.write_to_buffer(self.ssb_file_buffer)

    def create_ftable_trunc_dialog(self):
        print('resizing function table')
        if self.ssb_file is None:
            return
        oldlen = len(self.ssb_file.functable)
        prompt = f'Length (# entries) in function table is {oldlen}\nnew len:'
        newlen = tk.simpledialog.askinteger(title='', prompt=prompt, initialvalue=oldlen)
        if newlen < oldlen:
            text = 'This will delete data, continue?'
            confirm = tk.simpledialog.SimpleDialog(self, text, buttons=['Yes', 'No']).go()
            if confirm == 1:
                return
        if newlen < 0:
            text = 'Negative number interpreted as 0, continue?'
            confirm = tk.simpledialog.SimpleDialog(self, text, buttons=['Yes', 'No']).go()
            if confirm == 1:
                return

        deltalen = newlen - oldlen
        deltasize = deltalen * 24

        # TODO: do stuff


    def create_strings_trunc_dialog(self):
        print('resizing strings')
        if self.ssb_file is None:
            return

    def create_hook_edit_dialouge(self, hook):
        df = HookingFrame.HookDialog(self, hookoptions=Hooking.to_dict(hook), title='Edit Hook')
        nhook = df.result
        if nhook is not None:
            print("new hook made")
            self.hook_dict[self.ssb_file_name].remove(hook)
            self.hook_dict[self.ssb_file_name].append(nhook)
            print(self.hook_dict[self.ssb_file_name][0])
            self.update_hook_list()
        else:
            print("nope")

    def request_add_hook(self):
        # open a custom dialog
        print('adding dummy hook...')
        self.hook_dict[self.ssb_file_name].append(Hooking(0, 0, 0, 0))

        self.update_hook_list()

    def update_file_combo(self):
        # update options on the file combo
        fname_list = list(self.hook_dict.keys()) + ['']
        self.ssbfile_combo['values'] = fname_list
        self.ssbfile_combo.current(len(fname_list) - 1)

    def update_brief(self, func: SSBFunc):
        brief_format = (f"Function Name:\t{func.name}\n"
                        f"Start:\t0x{func.bounds[0]:X} (0x{to_offset(func.bounds[0]):X})\n"
                        f"End:\t0x{func.bounds[1]:X} (0x{to_offset(func.bounds[1]):X})\n"
                        f"Params:\t{func.numparams}\n"
                        f"Returns:\t{func.returns}\n\n"
                        f"Selected: \t{self.selected_index:X} ({to_offset(self.selected_index):X})\n"
                        f"")
        self.function_brief["text"] = brief_format

    def load_hooking_file(self):
        f = tkinter.filedialog.askopenfile(mode='r', initialdir='.', filetypes=[('json', '*.json')])
        if f is not None:
            self.hook_dict = json_to_hooks(json.load(f))
            f.close()
            self.update_file_combo()
            # would enable hook add button here, but not yet

    def set_all_text_widgets(self, prop, value):
        self.tabHeaderRawText[prop] = value
        self.tabBodyRawText[prop] = value
        self.tabBodyDecompText[prop] = value
        self.tabFTableRawText[prop] = value
        self.tabFTableFText[prop] = value
        self.tabStringsText[prop] = value

    def enable_text_widgets(self):
        self.set_all_text_widgets('state', 'normal')

    def disable_text_widgets(self):
        self.set_all_text_widgets('state', 'disabled')

    def clear_text_elements(self):
        self.tabHeaderRawText.delete('1.0', 'end')
        self.tabBodyRawText.delete('1.0', 'end')
        self.tabBodyDecompText.delete('1.0', 'end')
        self.tabFTableRawText.delete('1.0', 'end')
        self.tabFTableFText.delete('1.0', 'end')
        self.tabStringsText.delete('1.0', 'end')

    def do_popup_menu(self, event, index, tab):
        self.selected_index = index
        try:
            if tab == 0:    # header
                pass
            elif tab == 1:  # body
                self.bodyRawPopup.tk_popup(event.x_root, event.y_root)
            elif tab == 2:  # ftable
                self.FTableRawPopup.tk_popup(event.x_root, event.y_root)
            elif tab == 3:  # strings
                self.stringsPopup.tk_popup(event.x_root, event.y_root)
        finally:
            if tab == 0: pass
            elif tab == 1: self.bodyRawPopup.grab_release()
            elif tab == 2: self.FTableRawPopup.grab_release()
            elif tab == 3: self.stringsPopup.grab_release()
    
    def do_header_raw_action(self, event, index):
        print(event)

    def decomp_or_select(self, index):
        self.selected_index = index
        if self.decomp_start_index is None or not self.decomp_start_index <= index <= self.decomp_end_index:
            # decompile
            self.body_decompile()
        self.update_brief(self.get_function(index))
        self.mark_body_decomp_tags_by_index(index)

    def do_body_raw_action(self, event, index):
        if event.num == 1:
            self.decomp_or_select(index)
        if event.num == 3:
            self.do_popup_menu(event, index, 1)
    
    def do_decomp_func_name_action(self, event):
        # TODO: figure out function we're in
        if event.num == 3:
            self.ftitlePopup.tk_popup(event.x_root, event.y_root)

    def do_ftable_raw_action(self, event, fname):
        if event.num == 3:
            self.do_popup_menu(event, fname, 2)

    def do_strings_action(self, event, stroffset):
        # go find the string or smting or open a menu idk
        if event.num == 3:
            self.do_popup_menu(event, stroffset, 3)

    def create_and_bind_text_elements(self):
        # create and bind header text
        formatted_string = self.ssb_file.header.get_bytes().hex('\n', 16)
        self.tabHeaderRawText.insert('1.0', formatted_string, 'header-raw')
        # in case we wish to bind it

        # create and bind main body text
        formatted_string = ''
        for i in range(len(self.ssb_file.data)):
            formatted_string = '{:02X}{:02X}{:02X}{:02X}'.format(*self.ssb_file.data[i].to_bytes(4, 'little'))
            # create
            tagname = 'data-raw-{}'.format(i)
            if i % 4 == 0:
                self.tabBodyRawText.insert('end', '{:04x}: '.format(i))
            self.tabBodyRawText.insert('end', formatted_string, tagname)
            # bind
            self.tabBodyRawText.tag_bind(tagname, '<Button>', partial(self.do_body_raw_action, index=i))
            self.tabBodyRawText.insert('end', '\n' if (i + 1) % 4 == 0 else '  ')

        # create and bind function table
        print(self.ssb_file.functable.hashtable)
        for key in self.ssb_file.functable:
            all_val = self.ssb_file.functable.get_all(key)
            for i in range(len(all_val)):
                val = all_val[i]
                if len(all_val) > 1 and i != 0:
                    formatted_string = ('{:12s}: {:08X} (+{:08X}, *{}) (offset {:08X})\n'
                                        .format(key, val[0], to_offset(val[0]), i, val[2]))
                else:
                    formatted_string = ('{:12s}: {:08X} (+{:08X}) (offset {:08X})\n'
                                        .format(key, val[0], to_offset(val[0]), val[2]))
                tagname = 'functable-f-{}'.format(key)
                self.tabFTableRawText.insert('end', formatted_string, tagname)
                self.tabFTableRawText.tag_bind(tagname, '<Button>', partial(self.do_ftable_raw_action, fname=key))

        # create and bind strings
        # just list them idk
        for key in self.ssb_file.strings:
            val = self.ssb_file.strings[key]
            formatted_string = '+{:08X}: {}\n'.format(key, val.replace(b'\x01', b'<dialouge-break>'))
            tagname = 'string-f-{}'.format(key)
            self.tabStringsText.insert('end', formatted_string, tagname)
            self.tabStringsText.tag_bind(tagname, '<Button>', partial(self.do_strings_action, stroffset=key))

    ### HOOK EVENTS
    def get_last_unallocated_offset(self):
        last_unalloc = self.ssb_file.eof
        for hook in self.hook_dict[self.ssb_file_name]:
            if hook.allocated:
                last_unalloc = max(hook.hook_offset + hook.hook_length, last_unalloc)
        return last_unalloc

    def allocate_hook_event(self, hook: Hooking):
        print(hook.allocate(self.ssb_file_buffer))
        self.reload_file_from_buffer()

    def activate_hook_event(self, hook: Hooking):
        print(f'activating {hook}')
        hook.activate(self.ssb_file_buffer, hook.as_usable_command(struct.pack('<4B', 0x05, 0x00, 0x00, 0x00)))
        self.reload_file_from_buffer()

    def edit_hook_event(self, hook: Hooking):
        # open editing dialog
        print(f'editing {hook}')
        self.create_hook_edit_dialouge(hook)

    def delete_hook_event(self, hook: Hooking):
        self.hook_dict[self.ssb_file_name].remove(hook)
        self.update_hook_list()

    ### HOOK TABLE BUILDING

    def grid_table_header(self):
        tk.ttk.Label(self.scrollable_gridded_frame, text='Allocate').grid(row=0, column=0)
        tk.ttk.Label(self.scrollable_gridded_frame, text='Activate').grid(row=0, column=1)
        tk.ttk.Label(self.scrollable_gridded_frame, text='Offset').grid(row=0, column=2)
        tk.ttk.Label(self.scrollable_gridded_frame, text='Delete').grid(row=0, column=3)
        tk.ttk.Label(self.scrollable_gridded_frame, text='Orig Offset').grid(row=0, column=4)
        tk.ttk.Label(self.scrollable_gridded_frame, text='Description').grid(row=0, column=5)

    def update_hook_list(self):
        # remove old
        for slave in self.scrollable_gridded_frame.grid_slaves():
            slave.grid_forget()

        # add new stuff idk
        self.grid_table_header()
        row = 1
        for hook in self.hook_dict[self.ssb_file_name]:
            # make display for hook
            tk.ttk.Button(self.scrollable_gridded_frame, text='Allocate', command=partial(self.allocate_hook_event, hook=hook)).grid(row=row, column=0)
            tk.ttk.Button(self.scrollable_gridded_frame, text='Activate', command=partial(self.activate_hook_event, hook=hook)).grid(row=row, column=1)
            tk.ttk.Button(self.scrollable_gridded_frame, text='Edit', command=partial(self.edit_hook_event, hook=hook)).grid(row=row, column=2)
            tk.ttk.Button(self.scrollable_gridded_frame, text='Delete', command=partial(self.delete_hook_event, hook=hook)).grid(row=row, column=3)
            tk.ttk.Label(self.scrollable_gridded_frame, text='{:04X}'.format(hook.original_offset)).grid(row=row, column=4)
            tk.ttk.Label(self.scrollable_gridded_frame, text=hook.description).grid(row=row, column=5)
            row += 1

        # if there are no hooks, display default text
        if len(self.hook_dict[self.ssb_file_name]) == 0:
            self.default_scroll_text.grid(column=0, row=1, columnspan=3)

    def reload_file_from_buffer(self):
        # change so file length may be changed?
        # also need to change the way jumps work to allow jumping to hooks
        # also add a hook editor
        self.ssb_file = SSBFile(io.BytesIO(self.ssb_file_buffer), str_end=self.ssb_file.eof)

    def attempt_load_ssb_file(self, filename):
        # attempt to open and read into buffer
        try:
            f = open_ssb(filename, mode='rb')
            self.ssb_file = SSBFile(f)
            self.ssb_file_buffer = bytearray(self.ssb_file.eof)
            f.readinto(self.ssb_file_buffer)
            f.close()
            # attempt to load symbols
            if filename in self.symbols:
                self.ssb_file.bind_symbol_dict(self.symbols[filename]['lvars'])
                self.loaded_fnames = self.symbols[filename].setdefault('fnames', [])
            else:
                # prolly don't need to ask
                self.symbols[filename] = {'lvars': [], 'fnames': []}
            # load functions
            
        except IOError:
            print('uh oh, you found the toothpaste')
            return
        # idk if no errors go ahead
        self.ssb_file_name = filename
        # process functions
        self.reload_display()

    def reload_display(self):
        self.process_functions()
        # update hook list
        self.update_hook_list()
        # enable editing
        self.enable_text_widgets()
        # clear text fields
        self.clear_text_elements()
        # create and bind text
        self.create_and_bind_text_elements()
        self.disable_text_widgets()
        self.decomp_start_index = None
        self.hook_add_btn['state'] = 'normal'

    def ssbfile_selected(self, event):
        self.attempt_load_ssb_file(self.ssbfile_combo.get())

    def save_hooking_file(self):
        if self.hook_dict is None:
            print('whoops can\'t do that')
            return
        f = None
        try: 
            f = open("./hooks.json", mode='w')
        except IOError:
            f = open("./hook.json", mode="x")
        if f is not None:
            newhdict = self.hook_dict
            for k in newhdict:
                newhdict[k] = [Hooking.to_dict(i) for i in newhdict[k]]
            json.dump(newhdict, f)
            f.close()
            
    
    # push an individual file's locals back to our symbol object
    def push_lvars_to_symbols(self, filename):
        if self.ssb_file is None:
            return
        self.symbols.setdefault(filename, dict())['lvars'] = self.ssb_file.raw_symbols

    def save_symbol_file(self):
        print('SAVING')
        try:
            f = open("./symbols.json", mode='w')
            json.dump(self.symbols, f)
            f.close()
        except IOError:
            print("FAILED TO DUMP JSON")

    def save_to_file(self):
        if self.ssb_file is None:
            print("Can't do that")
            return
        confirm = tk.messagebox.askokcancel("Save changes to file?")
        if not confirm:
            print('Cancelled')
            return
        print('Saving to {}'.format(self.ssb_file_name))
        self.ssb_file.write_to_buffer(self.ssb_file_buffer)
        print('Opening...')
        fl = open(os.path.join(mod_fileroot, self.ssb_file_name), 'wb')
        fl.write(self.ssb_file_buffer)
        fl.close()
        self.reload_file_from_buffer()
        self.reload_display()
        self.body_decompile()
        self.decomp_or_select(self.selected_index)
    
    def on_closing(self, root):
        self.save_symbol_file()
        self.save_hooking_file()
        root.destroy()
    
    def add_ssb_to_hooks(self):
        if self.hook_dict is None:
            print('uh oh, no hooking file selected')
            return
        fname = tkinter.filedialog.askopenfilename(initialdir=mod_fileroot, filetypes=[('ssb', '*.ssb')])
        if fname is None:
            return

        rpath = os.path.relpath(fname, mod_fileroot)
        self.hook_dict[rpath] = []
        self.update_file_combo()


def format_bytes(b, seplen=16):
    for offset in range(0, len(b), seplen):
        print(f'{hex(offset)}: {b[offset:min(offset+seplen,len(b))].hex(",", 4)}')


def check_has_01_call(fname):
    ssbF = SSBFile(open(fname, 'rb'))
    for i in range(len(ssbF.data) - 2):
        token = SSBDecompiler.tokenize(ssbF.data, i, i)[0]
        # looking for idk
        if token[0] == 0x01:
            if token[2] == 0x1:
                if token[3] > 0x34:
                    print(f'FOUND {SSBDecompiler.str_token(token)} IN FILE {fname} AT COMMAND {i}')


if __name__ == '__main__':
    test_decompile_switch()
    s = 'atwme-s110'
    # initialize window
    root = tk.Tk()
    root.config()
    s = ttk.Style()
    s.configure('TFrame', background='black')
    s.configure('ScrolledText', background='black')
    hf = HookingFrame(root)
    hf.grid()
    root.mainloop()

