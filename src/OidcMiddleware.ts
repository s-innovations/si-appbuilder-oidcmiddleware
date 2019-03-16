
/// <reference types="oidc-client" />
import { Middleware, AppFunc } from "si-appbuilder";

//import { AppContext, AppMiddleware } from "../index";

export interface Subscription {
    id: string;
    subscriptionId: string;
    displayName: string;
}

export interface AppContextAuthorizationSuccess {

    isSignedIn: true;
    user: Oidc.User;
    subscription?: Subscription;
}
export interface AppContextAuthorizationFailed {

    isSignedIn: false;
    reason: string;
}

type Mutable<T> = {
    -readonly [P in keyof T]: T[P]
};



export interface OIDCAppContext {
    oidcOptions: Mutable<Oidc.UserManagerSettings>;
    userManager?: Oidc.UserManager;
    authorization?: AppContextAuthorizationSuccess | AppContextAuthorizationFailed;
}


function createAuthorization(ctx: OIDCAppContext, user: Oidc.User, err?: string) {
    if (user) {
        ctx.authorization = { user, isSignedIn: true };

    } else {
        ctx.authorization = { isSignedIn: false, reason: err };
    }
    return ctx;
}

declare global {
    interface ObjectConstructor {
        assign<T1, T2, T3>(a: T1, b: T2, c: T3): T1 & T2 & T3;
    }
}
if (typeof Object.assign != 'function') {
    Object.assign = function (target, varArgs) { // .length of function is 2
        'use strict';
        if (target == null) { // TypeError if undefined or null
            throw new TypeError('Cannot convert undefined or null to object');
        }

        var to = Object(target);

        for (var index = 1; index < arguments.length; index++) {
            var nextSource = arguments[index];

            if (nextSource != null) { // Skip over if undefined or null
                for (var nextKey in nextSource) {
                    // Avoid bugs when hasOwnProperty is shadowed
                    if (Object.prototype.hasOwnProperty.call(nextSource, nextKey)) {
                        to[nextKey] = nextSource[nextKey];
                    }
                }
            }
        }
        return to;
    };
}


let mgnr: Oidc.UserManager = null;


export async function OidcMiddleware<T extends OIDCAppContext>(ctx: T, next: AppFunc<T>) {

    if (mgnr === null) {
        let oidc = await import("oidc-client");
        // You can hook a logger to the library.
        // Conveniently, the methods exposed by the logger match
        // the `console` object
        oidc.Log.logger = console;

        let config = Object.assign({}, {
     //   authority: "",
     //   client_id: "",
            redirect_uri: `${window.location.protocol}//${window.location.host}${window.location.pathname}`,//  "http://localhost:5003/callback.html",
            response_type: "id_token token",
            scope: "openid profile",
            post_logout_redirect_uri: `${window.location.protocol}//${window.location.host}${window.location.pathname}`,
            silent_redirect_uri: `${window.location.protocol}//${window.location.host}${window.location.pathname}silent`,
            // Number of seconds before the token expires to trigger
            // the `tokenExpiring` event
            accessTokenExpiringNotificationTime: 300,
            // Do we want to renew the access token automatically when it's
            // about to expire?
            automaticSilentRenew: true,
            // Number of seconds before the token expires to trigger
            // the `tokenExpiring` event
            checkSessionInterval: 60000,
            loadUserInfo: true,
            // Do we want to filter OIDC protocal-specific claims from the response?
            filterProtocolClaims: true
        } as Oidc.UserManagerSettings, ctx.oidcOptions);

        //var config = extend(ctx.oidcOptions, {
        //    authority: "https://local.earthml.com:8500/identity/",
        //    client_id: "EarthML.Mapify",
        //    redirect_uri: `${window.location.protocol}//${window.location.host}${window.location.pathname}`,//  "http://localhost:5003/callback.html",
        //    response_type: "id_token token",
        //    scope: "openid profile api1",
        //    post_logout_redirect_uri: `${window.location.protocol}//${window.location.host}${window.location.pathname}`,
        //    silent_redirect_uri: `${window.location.protocol}//${window.location.host}${window.location.pathname}silent`,
        //    // Number of seconds before the token expires to trigger
        //    // the `tokenExpiring` event
        //    accessTokenExpiringNotificationTime: 4,
        //    // Do we want to renew the access token automatically when it's
        //    // about to expire?
        //    automaticSilentRenew: true,
        //    // Number of seconds before the token expires to trigger
        //    // the `tokenExpiring` event
        //    checkSessionInterval: 60000,

        //    // Do we want to filter OIDC protocal-specific claims from the response?
        //    filterProtocolClaims: true
        //} as Oidc.UserManagerSettings) as Oidc.UserManagerSettings;


        let mgr = mgnr = new oidc.UserManager(config) as Oidc.UserManager;

        // When a user logs in successfully or a token is renewed, the `userLoaded`
        // event is fired. the `addUserLoaded` method allows to register a callback to
        // that event

        mgr.events.addUserLoaded((loadedUser) => {
            createAuthorization(ctx, loadedUser);
        });

        // Same mechanism for when the automatic renewal of a token fails
        mgr.events.addSilentRenewError((error) => {
            console.error('error while renewing the access token', error);
        });

        // When the automatic session management feature detects a change in
        // the user session state, the `userSignedOut` event is fired.
        mgr.events.addUserSignedOut(() => {
            console.log('The user has signed out');

            mgr.removeUser().then(() => window.location.reload());
        });
    }
    Object.defineProperty(ctx, "userManager", { value: mgnr, enumerable: false });

    if (window.location.hash.indexOf("#id_token") === 0 || window.location.search.indexOf("code")) {

        await mgnr.signinRedirectCallback();
        history.pushState("", document.title, window.location.pathname);

        createAuthorization(ctx, await mgnr.getUser())

    } else {

        createAuthorization(ctx, await mgnr.getUser());


        if (ctx.authorization.isSignedIn) {

            if (ctx.authorization.user.expired) {

                await mgnr.signinSilent().then((user) => createAuthorization(ctx, user), (err) => createAuthorization(ctx, null, err));

            }
        } else {
            //  await mgr.signinSilent().then((user) => console.log(user), (err) => console.log(err));
        }

    }

    return await next(ctx);
} 