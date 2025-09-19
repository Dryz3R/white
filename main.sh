#!/bin/bash

PYTHON_SCRIPT="main.py"
PYTHON_EXEC="python3"
VENV_DIR="security-env"

check_installation() {
    if [ ! -d "$VENV_DIR" ] || [ ! -f "requirements.txt" ]; then
        echo "Installation non détectée. Lancement de l'installation..."
        ./install.sh
        exit 0
    fi
}

check_dependencies() {
    if ! command -v $PYTHON_EXEC &> /dev/null; then
        echo "Erreur: Python 3 n'est pas installé"
        exit 1
    fi

    if [ ! -f "$PYTHON_SCRIPT" ]; then
        echo "Erreur: Le fichier $PYTHON_SCRIPT n'existe pas"
        exit 1
    fi
}

activate_venv() {
    if [ -d "$VENV_DIR" ]; then
        source "$VENV_DIR/bin/activate"
    fi
}

show_help() {
    echo "Usage: main.sh [OPTION]"
    echo "Outil de sécurité avancé"
    echo ""
    echo "Options:"
    echo "  --install       Installer l'outil et les dépendances"
    echo "  --help          Afficher cette aide"
    echo "  --version       Afficher la version"
    echo ""
    echo "Exemples:"
    echo "  ./main.sh --install"
    echo "  ./main.sh --help"
    echo "  ./main.sh --net-scan 192.168.1.1"
}

case "$1" in
    --install)
        ./install.sh
        exit 0
        ;;
    --help)
        show_help
        exit 0
        ;;
    --version)
        $PYTHON_EXEC $PYTHON_SCRIPT --version
        exit 0
        ;;
    *)
        check_installation
        check_dependencies
        activate_venv
        exec $PYTHON_EXEC $PYTHON_SCRIPT "$@"
        ;;
esac