# TP1 - Analyse réseau et détection d'intrusions
# Programme pour capturer et analyser le trafic réseau
# TODO: améliorer la détection de certaines attaques

import argparse
import sys
from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report


def parse_arguments():
    # Configuration des arguments en ligne de commande
    parser = argparse.ArgumentParser(
        description="TP1 - Analyse de trafic réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python -m src.tp1.main
  python -m src.tp1.main -d 60
  python -m src.tp1.main -f tcp
  python -m src.tp1.main -o rapport_analyse.pdf
        """
    )
    
    # Durée de la capture
    parser.add_argument("-d", "--duration", type=int, default=30,
                        help="Durée de capture en secondes (défaut: 30)")
    
    # Filtre protocole
    parser.add_argument("-f", "--filter", type=str,
                        choices=["tcp", "udp", "icmp", "arp", "all"],
                        default="all",
                        help="Filtre de protocole (défaut: all)")
    
    # Fichier de sortie
    parser.add_argument("-o", "--output", type=str,
                        default="rapport_ids_ips.pdf",
                        help="Nom du fichier PDF de sortie")
    
    # Mode debug
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Afficher plus d'informations")
    
    return parser.parse_args()


def main():
    # Récupération des arguments
    args = parse_arguments()
    
    try:
        # Affichage des infos de démarrage
        print("="*60)
        logger.info("TP1 - IDS/IPS MAISON")
        logger.info("Analyse et détection d'attaques réseau")
        print("="*60)
        logger.info(f"Durée de capture: {args.duration} secondes")
        logger.info(f"Filtre de protocole: {args.filter}")
        logger.info(f"Rapport de sortie: {args.output}")
        print("="*60)
        
        # Etape 1: Init de la capture
        logger.info("[Étape 1/4] Initialisation de la capture réseau...")
        capture = Capture()
        
        # Vérification que l'interface a bien été sélectionnée
        if not capture.interface:
            logger.error("Aucune interface sélectionnée. Arrêt du programme.")
            sys.exit(1)
        
        # Etape 2: Lancement de la capture
        logger.info(f"[Étape 2/4] Capture du trafic réseau ({args.duration}s)...")
        capture.capture_trafic(duration=args.duration)
        
        # Check si on a bien capturé des paquets
        if len(capture.packets) == 0:
            logger.warning("Aucun paquet capturé. Vérifiez votre interface réseau.")
            sys.exit(1)
        
        # Etape 3: Analyse des paquets capturés
        logger.info("[Étape 3/4] Analyse du trafic et détection d'attaques...")
        
        # Application du filtre si nécessaire
        filtre = None
        if args.filter != "all":
            filtre = args.filter
        
        capture.analyse(filtre)
        
        # Récupération du résumé
        summary = capture.get_summary()
        
        # Affichage du résumé si mode verbeux
        if args.verbose:
            print(summary)
        
        # Affichage rapide des menaces détectées
        nb_menaces = len(capture.suspicious_activities)
        if nb_menaces > 0:
            logger.warning(f"ALERTE: {nb_menaces} activités suspectes détectées!")
            # Affichage de chaque menace
            for act in capture.suspicious_activities:
                logger.warning(f"  - {act['type']}: {act['details']}")
        else:
            logger.info("Aucune activité suspecte détectée.")
        
        # Etape 4: Génération du rapport PDF
        logger.info(f"[Étape 4/4] Génération du rapport PDF...")
        report = Report(capture, args.output, summary)
        
        # Génération du graphique
        report.generate("graph")
        # Génération du tableau
        report.generate("array")
        
        # Sauvegarde du rapport
        report.save(args.output)
        
        print("="*60)
        logger.info(f"Analyse terminée avec succès!")
        logger.info(f"Rapport disponible: {args.output}")
        print("="*60)
        
    except KeyboardInterrupt:
        # Gestion de l'interruption par l'utilisateur (Ctrl+C)
        logger.warning("\nANNULATION: Analyse interrompue par l'utilisateur.")
        sys.exit(0)
    except Exception as e:
        # Gestion des erreurs
        logger.error(f"ERREUR durant l'analyse: {str(e)}")
        if args.verbose:
            # Affichage de la stack trace complète en mode verbeux
            import traceback
            logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
