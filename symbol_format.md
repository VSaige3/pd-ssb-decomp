
# CURRENT SYMBOL FORMAT
## top: filename
### lvars: list
    - start_index: int
        - Represents index from top of commands to begin interpreting this symbol
    - stack_pos: int (signed)
        - Position in the stack frame of this variable. Negative is for locals, non-negative for parameters
    - symbol_dat
        - Data that gets piped directly into the constructor for the symbol. 
        - Current symbol data:
            - name: string
### fnames: list
    - start_index: int
        - start of the function duh
    - data: dict
        - name: string
        - numparams: int
        - returns: bool
        - name is preffered, numparams doesn't do anything

EXAMPLE:
{
    "Assets\\Data\\com\\ai\\eneprog006.ssb": {
        "lvars": [
            {
                "start_index": 10,
                "stack_pos": 0,
                "symbol_dat": {"name": "skill_id"}
            }
        ]
    }
}