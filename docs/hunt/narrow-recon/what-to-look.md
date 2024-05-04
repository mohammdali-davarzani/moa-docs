---
sidebar_position: 2
---

# What to look


### what is the  application used for? 
   - overall business logic 
   - the failure of confidentiality 
   - the failure of integirity 


### does the application have a certain threat model? 
   - revealing users' phone in authentication 
   - changing a property of my organization without permissions 

### how does the application pass data? 
   - legacy, all in one UI + backend 
   - simple web app + jQuery 
   - single page applications (SPA) + rest api 
   - single page applications (SPA) + graphQL
   - web-socket communication 

### how does the application handles users ? 
   - what are authentication schemes? 
   - Cookie, token, JWT, etc 
   - 2FA implemetations 
   - account delegations 
   - are there other user levels ? 
   - is there any authentication transfer ? 

### have been past security vulnearbilities ? 
   - public reports on the platform
   - collaborating with other hunters 


### does the application use third-parties?
   - for what purpose? saving data? 
   - do third-parties have bug bounty? 
   - are third-parties well-known or not?  

### is there any API documentation ? 
   - take much time to read and work with it 
   - may be more likely vulnerable 

### *eye catchings 
   - authentication class 
        - oauth ( all providers ) 
        - linking account
   - switching among other applications  : 
        - web to mobile, mobile to web , web to desktop, mobile to desktop
   - uploader sections 
   - links or HTML inputs 
   - application specific sections 
   - sensitive APIs 
   - JavaScript redirects 
   - postMessage 
   - unsual status codes 