# grades = (76, 81, 96)
# math, *history = grades
# print(math, history)
# import win32api
# def _drive_serial(drive_root: str) -> str | None:  # list =[1,2,3 ]   print(list[0]) 
#     try:
#         return str(win32api.GetVolumeInformation(drive_root)) # volume name, serial number, maximum file name length, file system flags, and file system name.
#     except Exception:
#         return None  
    
# print(_drive_serial("F:\\"))     
# import numpy as np
# import random
# import time

# PLAYER = 'X'
# COMPUTER = 'O'
# board = None

# def resteBoard():
#     global board
#     board = np.full((3, 3), ' ')

# def printBoard():
#     print(f" {board[0,0]} | {board[0,1]} | {board[0,2]}")
#     print("---|---|---")
#     print(f" {board[1,0]} | {board[1,1]} | {board[1,2]}")
#     print("---|---|---")
#     print(f" {board[2,0]} | {board[2,1]} | {board[2,2]}")
#     print("\n")

# def checkFreeSpace():
#     return np.count_nonzero(board == ' ')

# def playerMove():
#     while True:
#         try:
#             x = int(input("Enter row (1-3): ")) - 1
#             y = int(input("Enter column (1-3): ")) - 1
#             if x not in range(3) or y not in range(3):
#                 print(" Out of bounds! Try again.")
#             elif board[x][y] != ' ':
#                 print(" Cell taken! Try again.")
#             else:
#                 board[x][y] = PLAYER
#                 break
#         except ValueError:
#             print(" Invalid input!")

# def computerMove():
#     if checkFreeSpace() == 0:
#         return
#     while True:
#         x = random.randint(0, 2)
#         y = random.randint(0, 2)
#         if board[x][y] == ' ':
#             board[x][y] = COMPUTER
#             print(f"Computer moved to ({x+1}, {y+1})")
#             break

# def checkWin():
#     for i in range(3):
#         if board[i, 0] == board[i, 1] == board[i, 2] != ' ':
#             return board[i, 0]
#         if board[0, i] == board[1, i] == board[2, i] != ' ':
#             return board[0, i]
#     if board[0, 0] == board[1, 1] == board[2, 2] != ' ':
#         return board[0, 0]
#     if board[0, 2] == board[1, 1] == board[2, 0] != ' ':
#         return board[0, 2]
#     return None

# def printWinner(winner):
#     if winner == PLAYER:
#         print(" Player wins!")
#     elif winner == COMPUTER:
#         print(" Computer wins!")
#     else:
#         print(" It's a draw!")

# def main():
#     resteBoard()
#     winner = None

#     while winner is None and checkFreeSpace() > 0:
#         printBoard()
#         playerMove()
#         winner = checkWin()
#         if winner or checkFreeSpace() == 0:
#             break
#         computerMove()
#         winner = checkWin()

#     printBoard()
#     printWinner(winner)

# if __name__ == "__main__":
#     main()



flag = True
while flag:
    print("Hello")
    