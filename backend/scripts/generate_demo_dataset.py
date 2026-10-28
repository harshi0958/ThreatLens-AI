from backend.app.services.demo_dataset import generate_demo_dataset

if __name__ == '__main__':
    path = generate_demo_dataset()
    print(f'Synthetic sample dataset generated at: {path}')
