import pygame
from pwn import remote
import pickle
import sys

# Initialize connection to the service
io = remote('202.112.238.82', 13370)
print(io.recvuntil(b'> ').decode())
screen_num = 1
visited_squares = set()
teleports = set()
walls = set()
try:
    teleports = pickle.load(open('teleports.pkl', 'rb'))
except:
    pass


def interact(move):
    try:
        io.sendline(move.encode())
        response = io.recvuntil(b'> ')
        print(response)
        if response.startswith(b'Sorry'):
            return 1
        elif response.startswith(b'It seems'):
            return 2
        else:
            return 0
    except EOFError:
        pickle.dump(walls, open('log.pkl', 'wb'))


# Initialize Pygame
pygame.init()

# Screen dimensions
WIDTH, HEIGHT = 800, 600
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Blind Maze Game")

# Square settings
square_size = 30
player_color = (0, 0, 255)  # Blue color for player
wall_color = (255, 0, 0)    # Red color for walls

# Camera offset
camera_x, camera_y = 0, 0

if 'continue' in sys.argv:
    walls = pickle.load(open(f'walls.pkl', 'rb'))
    visited_squares = pickle.load(open(f'vs.pkl', 'rb'))
elif 'load' in sys.argv:
    screen_num = int(sys.argv[2])
    walls = pickle.load(open(f'{screen_num}.pkl', 'rb'))
# Clock to control frame rate
clock = pygame.time.Clock()


def move_square(direction):
    global camera_x, camera_y, walls, screen_num, visited_squares
    response = interact(direction)

    current_square_x = WIDTH // 2 - square_size // 2 - camera_x
    current_square_y = HEIGHT // 2 - square_size // 2 - camera_y
    if response == 0:
        visited_squares.add((current_square_x, current_square_y))
        # Successful move: Adjust camera position
        if direction == 'w':
            camera_y += square_size
        elif direction == 's':
            camera_y -= square_size
        elif direction == 'a':
            camera_x += square_size
        elif direction == 'd':
            camera_x -= square_size
    elif response == 1:
        # Hit a wall, add a wall line directly in front of the player's current position
        wall_x = WIDTH // 2 - square_size // 2 - camera_x
        wall_y = HEIGHT // 2 - square_size // 2 - camera_y
        if direction == 'w':
            walls.add((wall_x, wall_y, wall_x + square_size, wall_y))
        elif direction == 's':
            walls.add((wall_x, wall_y + square_size, wall_x +
                      square_size, wall_y + square_size))
        elif direction == 'a':
            walls.add((wall_x, wall_y, wall_x, wall_y + square_size))
        elif direction == 'd':
            walls.add((wall_x + square_size, wall_y, wall_x +
                      square_size, wall_y + square_size))
    elif response == 2:
        # Save current coordinates
        teleport_square_x = WIDTH // 2 - square_size // 2 - camera_x
        teleport_square_y = HEIGHT // 2 - square_size // 2 - camera_y
        if direction == 'w':
            teleport_square_y -= square_size
        elif direction == 's':
            teleport_square_y += square_size
        elif direction == 'a':
            teleport_square_x -= square_size
        elif direction == 'd':
            teleport_square_x += square_size
        teleports.add((teleport_square_x, teleport_square_y))
        # Teleported: Reset camera and walls
        camera_x, camera_y = 0, 0
        pickle.dump(walls, open(f'{screen_num}.pkl', 'wb'))
        pickle.dump(visited_squares, open(f'vs.pkl', 'wb'))
        pickle.dump(teleports, open(f'teleports.pkl', 'wb'))
        screen_num += 1
        walls.clear()
        visited_squares.clear()
        teleports.clear()
        try:
            walls = pickle.load(open(f'{screen_num + 1}.pkl', 'rb'))
        except:
            pass


running = True
while running:
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False

        if event.type == pygame.KEYDOWN:
            if event.key == pygame.K_w:
                move_square('w')
            elif event.key == pygame.K_s:
                move_square('s')
            elif event.key == pygame.K_a:
                move_square('a')
            elif event.key == pygame.K_d:
                move_square('d')
            elif event.key == pygame.K_e:
                pickle.dump(walls, open('walls.pkl', 'wb'))
                pickle.dump(visited_squares, open('vs.pkl', 'wb'))
                pickle.dump(teleports, open('teleports.pkl', 'wb'))

    screen.fill((0, 0, 0))  # Fill the screen with black
    # Draw teleports
    for teleport in teleports:
        pygame.draw.rect(screen, (255, 255, 0),
                         (teleport[0] + camera_x, teleport[1] + camera_y, square_size, square_size))

    for square in visited_squares:
        pygame.draw.rect(screen, (255, 255, 255),
                         (square[0] + camera_x, square[1] + camera_y, square_size, square_size))
    # Draw walls
    for wall in walls:
        pygame.draw.line(screen, wall_color, (wall[0] + camera_x, wall[1] + camera_y),
                         (wall[2] + camera_x, wall[3] + camera_y), 4)

    # Draw the player square (always in the center)
    pygame.draw.rect(screen, player_color, (WIDTH // 2 - square_size //
                     2, HEIGHT // 2 - square_size // 2, square_size, square_size))

    pygame.display.flip()
    clock.tick(60)

pygame.quit()
