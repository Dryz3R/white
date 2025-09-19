#!/bin/bash

PYTHON_SCRIPT="main.py"
PYTHON_EXEC="python3"

if ! command -v $PYTHON_EXEC &> /dev/null; then
    echo "Erreur: Python 3 n'est pas installé"
    exit 1
fi

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "Erreur: Le fichier $PYTHON_SCRIPT n'existe pas"
    exit 1
fi

exec $PYTHON_EXEC $PYTHON_SCRIPT "$@"