<?php

namespace App\Tests\Functional\Controller;

use App\Entity\Enum\ProfileDeclarant;
use App\Entity\Enum\SignalementStatus;
use App\Entity\Signalement;
use App\Tests\UserHelper;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;

/**
 * Test de régression sécurité — IDOR front-usager.
 *
 * SignalementFoVoter::canUsagerEdit() et canUsagerCompleteDossier() vérifient
 * uniquement le statut du signalement et isLogementVacant, mais jamais que le
 * code de suivi de l'usager authentifié (firewall code_suivi) correspond au
 * signalement visé par l'URL (contrairement à canUsagerView()).
 *
 * Un usager légitimement authentifié sur SON dossier A doit donc se voir
 * refuser (403) :
 * - la lecture des formulaires de complétion d'un dossier B (divulgation des
 *   coordonnées de l'occupant de B, pré-remplies dans le formulaire) ;
 * - l'écriture sur le dossier B (ex. GET /bailleur-prevenu qui passe
 *   isProprioAverti à true sans aucun jeton CSRF).
 *
 * Ces tests DOIVENT échouer tant que le correctif d'appartenance du code de
 * suivi n'est pas appliqué.
 */
class SignalementEditAccessOtherDossierTest extends WebTestCase
{
    use UserHelper;

    protected function setUp(): void
    {
        self::ensureKernelShutdown();
    }

    /**
     * @return array{0: Signalement, 1: Signalement}
     */
    private function givenTwoActiveLocataireDossiers(EntityManagerInterface $entityManager): array
    {
        /** @var array<Signalement> $signalements */
        $signalements = $entityManager->getRepository(Signalement::class)->findBy(
            [
                'statut' => SignalementStatus::ACTIVE,
                'profileDeclarant' => ProfileDeclarant::LOCATAIRE,
            ],
            ['id' => 'ASC'],
            2
        );
        $this->assertCount(2, $signalements, 'Les fixtures doivent fournir au moins deux signalements ACTIVE/LOCATAIRE.');
        $this->assertNotSame(
            $signalements[0]->getCodeSuivi(),
            $signalements[1]->getCodeSuivi(),
            'Les deux dossiers doivent avoir des codes de suivi distincts.'
        );

        return $signalements;
    }

    public function testUsagerCannotReadCompletionFormOfOtherDossier(): void
    {
        $client = static::createClient();

        /** @var EntityManagerInterface $entityManager */
        $entityManager = static::getContainer()->get('doctrine')->getManager();
        [$signalementA, $signalementB] = $this->givenTwoActiveLocataireDossiers($entityManager);

        // Marqueurs distinctifs sur les données personnelles de l'occupant « victime » (dossier B)
        $signalementB->setNomOccupant('Victimeidor');
        $signalementB->setTelOccupant('0698765432');
        $entityManager->flush();

        // L'usager A s'authentifie normalement sur SON dossier A (initiales + CP de A uniquement)
        $client->loginUser($this->getSignalementUser($signalementA), 'code_suivi');

        /** @var RouterInterface $router */
        $router = static::getContainer()->get(RouterInterface::class);
        $url = $router->generate('front_suivi_signalement_complete_occupant', [
            'code' => $signalementB->getCodeSuivi(),
        ]);

        $client->request('GET', $url);

        $leaked = str_contains((string) $client->getResponse()->getContent(), '0698765432');
        $this->assertSame(
            Response::HTTP_FORBIDDEN,
            $client->getResponse()->getStatusCode(),
            sprintf(
                'IDOR (divulgation) : un usager authentifié sur le dossier A (code %s) a reçu le formulaire de'
                .' complétion du dossier B (code %s) — HTTP %d au lieu de 403, coordonnées de l\'occupant de B %s'
                .' dans la page (nom « Victimeidor », téléphone « 0698765432 »).',
                $signalementA->getCodeSuivi(),
                $signalementB->getCodeSuivi(),
                $client->getResponse()->getStatusCode(),
                $leaked ? 'DIVULGUÉES' : 'absentes'
            )
        );

        // Ceinture et bretelles : même si le code de statut HTTP change, aucune donnée de B ne doit fuiter.
        $this->assertStringNotContainsString(
            '0698765432',
            (string) $client->getResponse()->getContent(),
            'Le téléphone de l\'occupant du dossier B ne doit pas être lisible par l\'usager du dossier A.'
        );
        $this->assertStringNotContainsString(
            'Victimeidor',
            (string) $client->getResponse()->getContent(),
            'Le nom de l\'occupant du dossier B ne doit pas être lisible par l\'usager du dossier A.'
        );
    }

    public function testUsagerCannotWriteBailleurPrevenuOnOtherDossier(): void
    {
        $client = static::createClient();

        /** @var EntityManagerInterface $entityManager */
        $entityManager = static::getContainer()->get('doctrine')->getManager();
        [$signalementA, $signalementB] = $this->givenTwoActiveLocataireDossiers($entityManager);

        $signalementB->setIsProprioAverti(false);
        $entityManager->flush();

        $client->loginUser($this->getSignalementUser($signalementA), 'code_suivi');

        /** @var RouterInterface $router */
        $router = static::getContainer()->get(RouterInterface::class);
        $url = $router->generate('front_suivi_signalement_bailleur_prevenu', [
            'code' => $signalementB->getCodeSuivi(),
        ]);

        // Simple GET : aucun jeton CSRF ni identifiant (initiales/CP) du dossier B n'est fourni
        $client->request('GET', $url);

        $entityManager->clear();
        /** @var Signalement $signalementBReloaded */
        $signalementBReloaded = $entityManager->getRepository(Signalement::class)->find($signalementB->getId());

        $this->assertSame(
            Response::HTTP_FORBIDDEN,
            $client->getResponse()->getStatusCode(),
            sprintf(
                'IDOR (écriture sans CSRF) : le GET /suivre-mon-signalement/{code}/bailleur-prevenu du dossier B'
                .' (code %s) par l\'usager du dossier A (code %s) a répondu HTTP %d (Location: %s) et isProprioAverti'
                .' de B vaut désormais %s — le dossier de B a été modifié sans jamais fournir ses identifiants.',
                $signalementB->getCodeSuivi(),
                $signalementA->getCodeSuivi(),
                $client->getResponse()->getStatusCode(),
                $client->getResponse()->headers->get('Location') ?? '-',
                var_export($signalementBReloaded->getIsProprioAverti(), true)
            )
        );

        $this->assertFalse(
            (bool) $signalementBReloaded->getIsProprioAverti(),
            'Le dossier B ne doit pas pouvoir être modifié par l\'usager du dossier A : isProprioAverti doit rester false.'
        );
    }

    public function testCompletionFormWithUnknownCodeIsNotServed(): void
    {
        // Contrôle négatif : un code de suivi inexistant ne doit rien servir.
        // C'est donc bien la résolution du dossier d'un AUTRE usager qui crée la fuite,
        // pas une absence totale de contrôle sur la route.
        $client = static::createClient();

        /** @var EntityManagerInterface $entityManager */
        $entityManager = static::getContainer()->get('doctrine')->getManager();
        [$signalementA] = $this->givenTwoActiveLocataireDossiers($entityManager);
        $client->loginUser($this->getSignalementUser($signalementA), 'code_suivi');

        /** @var RouterInterface $router */
        $router = static::getContainer()->get(RouterInterface::class);
        $url = $router->generate('front_suivi_signalement_complete_occupant', [
            'code' => 'code-de-suivi-inexistant',
        ]);

        $client->request('GET', $url);

        $this->assertNotSame(
            Response::HTTP_OK,
            $client->getResponse()->getStatusCode(),
            'Un code de suivi inconnu ne doit pas afficher le formulaire de complétion.'
        );
    }
}
