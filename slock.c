/* See LICENSE file for license details. */
#define _XOPEN_SOURCE 500
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <sys/mman.h> // mlock()
#include <security/pam_appl.h> 

#ifdef __GNUC__
    #define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
    #define UNUSED(x) UNUSED_ ## x
#endif

typedef struct {
    int screen;
    Window root, win;
    Pixmap pmap;
    unsigned long colors[2];
} Lock;

static int conv_callback(int num_msgs, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);

pam_handle_t *pam_handle;
struct pam_conv conv = { conv_callback, NULL };

static Lock **locks;
static int nscreens;
static Bool running = True;

/* Holds the password you enter */
static char password[256];

/*
 * Clears the memory which stored the password to be a bit safer against
 * cold-boot attacks.
 *
 */
static void
clear_password_memory(void) {
    /* A volatile pointer to the password buffer to prevent the compiler from
     * optimizing this out. */
    volatile char *vpassword = password;
    for (unsigned int c = 0; c < sizeof(password); c++)
        /* rewrite with random values */
        vpassword[c] = rand();
}

/*
 * Callback function for PAM. We only react on password request callbacks.
 *
 */
static int
conv_callback(int num_msgs, const struct pam_message **msg, struct pam_response **resp, void *UNUSED(appdata_ptr)) {
    if (num_msgs == 0)
        return PAM_BUF_ERR;

    // PAM expects an array of responses, one for each message
    if ((*resp = calloc(num_msgs, sizeof(struct pam_message))) == NULL)
        return PAM_BUF_ERR;

    for (int i = 0; i < num_msgs; i++) {
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF &&
            msg[i]->msg_style != PAM_PROMPT_ECHO_ON)
            continue;

        // return code is currently not used but should be set to zero
        resp[i]->resp_retcode = 0;
        if ((resp[i]->resp = strdup(password)) == NULL) {
            free(*resp);
            return PAM_BUF_ERR;
        }
    }

    return PAM_SUCCESS;
}

static void
die(const char *errstr, ...) {
    va_list ap;

    va_start(ap, errstr);
    vfprintf(stderr, errstr, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

static void
readpw(Display *dpy)
{
    int screen;
    unsigned int len, llen;
    KeySym ksym;
    XEvent ev;

    len = llen = 0;
    running = True;

    /* As "slock" stands for "Simple X display locker", the DPMS settings
     * had been removed and you can set it with "xset" or some other
     * utility. This way the user can easily set a customized DPMS
     * timeout. */
    while(running && !XNextEvent(dpy, &ev)) {
        if(ev.type == KeyPress) {
	    char inputChar = 0;
	    XLookupString(&ev.xkey, &inputChar, sizeof(inputChar), &ksym, 0);
            if(IsKeypadKey(ksym)) {
                if(ksym == XK_KP_Enter)
                    ksym = XK_Return;
                else if(ksym >= XK_KP_0 && ksym <= XK_KP_9)
                    ksym = (ksym - XK_KP_0) + XK_0;
            }
            if(IsFunctionKey(ksym) || IsKeypadKey(ksym)
                    || IsMiscFunctionKey(ksym) || IsPFKey(ksym)
                    || IsPrivateKeypadKey(ksym))
                continue;
            switch(ksym) {
            case XK_Return:
                password[len] = 0;
                if(pam_authenticate(pam_handle, 0) == PAM_SUCCESS) {
		    clear_password_memory();
                    running = False;
		} else {
		    XBell(dpy, 100);
		    running = True;
		}
                len = 0;
                break;
            case XK_Escape:
                len = 0;
                break;
            case XK_BackSpace:
                if(len)
                    --len;
                break;
            default:
                if (isprint(inputChar) && (len + sizeof(inputChar) < sizeof password)) {
                    memcpy(password + len, &inputChar, sizeof(inputChar));
                    len += sizeof(inputChar);
                }
                break;
            }
            if(llen == 0 && len != 0) {
                for(screen = 0; screen < nscreens; screen++) {
                    XSetWindowBackground(dpy, locks[screen]->win, locks[screen]->colors[1]);
                    XClearWindow(dpy, locks[screen]->win);
                }
            } else if(llen != 0 && len == 0) {
                for(screen = 0; screen < nscreens; screen++) {
                    XSetWindowBackground(dpy, locks[screen]->win, locks[screen]->colors[0]);
                    XClearWindow(dpy, locks[screen]->win);
                }
            }
            llen = len;
        }
        else for(screen = 0; screen < nscreens; screen++)
            XRaiseWindow(dpy, locks[screen]->win);
    }
}

static void
unlockscreen(Display *dpy, Lock *lock) {
    if(dpy == NULL || lock == NULL)
        return;

    XUngrabPointer(dpy, CurrentTime);
    XFreeColors(dpy, DefaultColormap(dpy, lock->screen), lock->colors, 2, 0);
    XFreePixmap(dpy, lock->pmap);
    XDestroyWindow(dpy, lock->win);

    free(lock);
}

static Lock *
lockscreen(Display *dpy, int screen) {
    char curs[] = {0, 0, 0, 0, 0, 0, 0, 0};
    unsigned int len;
    Lock *lock;
    XColor color, dummy;
    XSetWindowAttributes wa;
    Cursor invisible;

    if(dpy == NULL || screen < 0)
        return NULL;

    lock = malloc(sizeof(Lock));
    if(lock == NULL)
        return NULL;

    lock->screen = screen;

    lock->root = RootWindow(dpy, lock->screen);

    /* init */
    wa.override_redirect = 1;
    wa.background_pixel = BlackPixel(dpy, lock->screen);
    lock->win = XCreateWindow(dpy, lock->root, 0, 0, DisplayWidth(dpy, lock->screen), DisplayHeight(dpy, lock->screen),
            0, DefaultDepth(dpy, lock->screen), CopyFromParent,
            DefaultVisual(dpy, lock->screen), CWOverrideRedirect | CWBackPixel, &wa);
    XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen), COLOR2, &color, &dummy);
    lock->colors[1] = color.pixel;
    XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen), COLOR1, &color, &dummy);
    lock->colors[0] = color.pixel;
    lock->pmap = XCreateBitmapFromData(dpy, lock->win, curs, 8, 8);
    invisible = XCreatePixmapCursor(dpy, lock->pmap, lock->pmap, &color, &color, 0, 0);
    XDefineCursor(dpy, lock->win, invisible);
    XMapRaised(dpy, lock->win);
    for(len = 1000; len; len--) {
        if(XGrabPointer(dpy, lock->root, False, ButtonPressMask | ButtonReleaseMask | PointerMotionMask,
            GrabModeAsync, GrabModeAsync, None, invisible, CurrentTime) == GrabSuccess)
            break;
        usleep(1000);
    }
    if(running && (len > 0)) {
        for(len = 1000; len; len--) {
            if(XGrabKeyboard(dpy, lock->root, True, GrabModeAsync, GrabModeAsync, CurrentTime)
                == GrabSuccess)
                break;
            usleep(1000);
        }
    }

    running &= (len > 0);
    if(!running) {
        unlockscreen(dpy, lock);
        lock = NULL;
    }
    else 
        XSelectInput(dpy, lock->root, SubstructureNotifyMask);

    return lock;
}

int
main(int argc, char **argv) {
    Display *dpy;
    int screen;

    if((argc == 2) && !strcmp("-v", argv[1]))
        die("slock-%s, © 2006-2012 Anselm R Garbe\n", VERSION);

    if(!(dpy = XOpenDisplay(0)))
        die("slock: cannot open display\n");
    /* Get the number of screens in display "dpy" and blank them all. */
    nscreens = ScreenCount(dpy);
    locks = malloc(sizeof(Lock *) * nscreens);
    if(locks == NULL)
        die("slock: malloc: %s\n", strerror(errno));
    int nlocks = 0;
    for(screen = 0; screen < nscreens; screen++) {
        if ( (locks[screen] = lockscreen(dpy, screen)) != NULL)
            nlocks++;
    }
    XSync(dpy, False);

    /* Did we actually manage to lock something? */
    if (nlocks == 0) { // nothing to protect
        free(locks);
        XCloseDisplay(dpy);
        return 1;
    }

    char* username;
    if ((username = getenv("USER")) == NULL)
        die("USER environment variable not set, please set it.\n");

    /* set up PAM */
    {
        int ret = pam_start("slock", username, &conv, &pam_handle);
        if (ret != PAM_SUCCESS)
            die("PAM: %s\n", pam_strerror(pam_handle, ret));
    }

    /* Lock the area where we store the password in memory, we don’t want it to
     * be swapped to disk. Since Linux 2.6.9, this does not require any
     * privileges, just enough bytes in the RLIMIT_MEMLOCK limit. */
    if (mlock(password, sizeof(password)) != 0)
        die("Could not lock page in memory, check RLIMIT_MEMLOCK\n");

    /* Everything is now blank. Now wait for the correct password. */
    readpw(dpy);

    /* Password ok, unlock everything and quit. */
    for(screen = 0; screen < nscreens; screen++)
        unlockscreen(dpy, locks[screen]);

    free(locks);
    XCloseDisplay(dpy);

    return 0;
}
