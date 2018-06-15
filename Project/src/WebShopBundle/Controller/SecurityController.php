<?php

namespace WebShopBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Config\Definition\Exception\Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use WebShopBundle\Form\LoginForm;
use WebShopBundle\Entity\User;
use Symfony\Component\HttpFoundation\Cookie;

class SecurityController extends Controller
{
    /**
     * @Route("/login", name="security_login")
     * @return Response
     */
    public function loginAction(Request $request)
    {
        //Require encoder service
        $encoderService = $this->get("web_shop.security.encoder");

        $form = $this->createForm(LoginForm::class);

        $form->handleRequest($request);
         //System validates the input data
        if ($form->isSubmitted() && $form->isValid()) {
            //System gets token from Sessions
            $csrf_token = $this->container->get("session")->get("csrf_token");
            //System gets the token provided by the user
            $token = $request->request->get('csrf_token');
            //Compare  session token and token provided by user
            if($csrf_token === $token){
                $data = $form->getData();
                $username = $data["_username"];
                //System gets user entity on email provided
                $user = $this->getDoctrine()->getRepository(User::class)
                    ->findOneBy([
                        "email" => $username
                    ]);
                $password = $data["_password"];
                 //If user found
                if($user){
                     //#Password provided comparing to password in the data base
                    if ($encoderService->isPasswordValid($user->getPassword(), $password,$this->container->getParameter('salt'))) {
                        $this->container->get("session")->set('user',$user);
                        $cookie = new Cookie(
                            'security_cookie',	// Cookie name.
                            $user->getFullName(),	// Cookie value.
                            time() + (300)	// Expires 5 minutes
                        );
                        $res = new Response();
                        $res->headers->setCookie( $cookie );
                        $res->send();
                         //Check the user has the admin role

                        foreach ($user->getRoles() as $role){
                            if($role->getName()=='ROLE_EDITOR'){
                                $this->container->get("session")->set('role','Editor');
                            }
                        }

                        $this->container->get("session")->getFlashBag()->add("success", "Logged in successfully!");
                        //The user will be redirected to the home page
                        return $this->redirectToRoute("homepage");
                    }
                }
                $this->addFlash("success", "Error with the credentials!");
                return $this->redirectToRoute("security_login");
            }else{
                $this->addFlash("success", "Error with the token!");
                return $this->redirectToRoute("security_login");
            }
        }
        //System creates CSRF token
        $csrf_token = md5(openssl_random_pseudo_bytes(32));
        //System puts Token into session
        $this->container->get("session")->set('csrf_token',$csrf_token);
         //System renders the Login page
        return $this->render("@WebShop/security/login.html.twig", [
            "login_form" => $form->createView(),
            "csrf_token" => $csrf_token
        ]);
    }

     /**
     * @Route("/logout", name="security_logout")
     * @Method("GET")
     */
    public function logoutAction()
    {

        $this->container->get("session")->clear();
        return $this->redirectToRoute("homepage");

        throw new \Exception("This page should not be reached.");
    }
}
