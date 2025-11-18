# rock paper scissors :3

simple multiplayer rock paper scissors game with timer

## features
- 10 second timer
- auto-pick if you run out of time
- shareable room links
- black and white minimal design
- cute emoticons :'*

## deploy to render (free)

1. create a github account if you don't have one
2. create a new repository on github
3. in this folder, run:
```bash
git init
git add .
git commit -m "initial commit :3"
git branch -M main
git remote add origin YOUR_GITHUB_REPO_URL
git push -u origin main
```

4. go to https://render.com and sign up (use your github account)
5. click "New +" and select "Web Service"
6. connect your github repository
7. use these settings:
   - name: rps (or whatever you want)
   - environment: Node
   - build command: `npm install`
   - start command: `npm start`
8. click "Create Web Service"
9. wait for it to deploy (takes a few minutes)
10. your game will be live at the url render gives you :3

## deploy to glitch (easier, instant)

1. go to https://glitch.com
2. click "New Project" > "Import from GitHub"
3. paste your github repo url
4. it will auto-deploy
5. click "Show" to see your live game :3

## run locally

```bash
npm install
npm start
```

open http://localhost:3000
