import {Router, Request, Response} from 'express';
import {FeedItem} from '../models/FeedItem';
import {NextFunction} from 'connect';
import * as jwt from 'jsonwebtoken';
import * as AWS from '../../../../aws';
import * as c from '../../../../config/config';

const router: Router = Router();

const NO_AUTH_HEADER = 'No authorization headers.';
const MALFORMED = 'Malformed token.';
const AUTH_FAILED = 'Failed to authenticate.';
const CAPTION_MALFORMED = 'Caption is required or malformed.';
const REQ_URL = 'File url is required.';

export function requireAuth(req: Request, res: Response, next: NextFunction) {

  log(req, 'Starting authorization process');

  if (!req.headers || !req.headers.authorization) {
    log(req, NO_AUTH_HEADER);
    return res.status(401).send({message: NO_AUTH_HEADER});
  }

  const tokenBearer = req.headers.authorization.split(' ');
  if (tokenBearer.length != 2) {
    log(req, MALFORMED);
    return res.status(401).send({message: MALFORMED});
  }

  const token = tokenBearer[1];
  return jwt.verify(token, c.config.jwt.secret, (err, decoded) => {
    if (err) {
      log(req, AUTH_FAILED);
      return res.status(500).send({auth: false, message: AUTH_FAILED});
    }

    log(req, 'Authentiation successful');
    return next();
  });
}

// Get all feed items
router.get('/', async (req: Request, res: Response) => {  

  log(req, 'Fetching feed');

  const items = await FeedItem.findAndCountAll({order: [['id', 'DESC']]});

  log(req, `Items fetched: ${items.count}`);

  items.rows.map((item) => {
    if (item.url) {
      item.url = AWS.getGetSignedUrl(item.url);
    }
  });
  res.send(items);
});

// Get a feed resource
router.get('/:id',
    async (req: Request, res: Response) => {
      const {id} = req.params;

      log(req, `Getting feedItem with id ${id}`);
      const item = await FeedItem.findByPk(id);
      log(req, `Returned feedItem with id ${id}`);

      res.send(item);
    });

// Get a signed url to put a new item in the bucket
router.get('/signed-url/:fileName',
    requireAuth,
    async (req: Request, res: Response) => {
      const {fileName} = req.params;

      log(req, `Generating a signedUrl for ${fileName}`);
      const url = AWS.getPutSignedUrl(fileName);
      log(req, `Generated a signedUrl for ${fileName}`);

      res.status(201).send({url: url});
    });

// Create feed with metadata
router.post('/',
    requireAuth,
    async (req: Request, res: Response) => {
      const caption = req.body.caption;
      const fileName = req.body.url; // same as S3 key name

      log(req, `Creating feed for ${fileName}`);

      if (!caption) {
        log(req, CAPTION_MALFORMED);
        return res.status(400).send({message: CAPTION_MALFORMED});
      }

      if (!fileName) {
        log(req, REQ_URL);
        return res.status(400).send({message: REQ_URL});
      }

      const item = await new FeedItem({
        caption: caption,
        url: fileName,
      });

      log(req, 'Saving item');
      const savedItem = await item.save();
      log(req, 'Item saved');

      log(req, `Signing url for ${savedItem.url}`);
      savedItem.url = AWS.getGetSignedUrl(savedItem.url);
      log(req, `Signed url for ${savedItem.url}`);

      res.status(201).send(savedItem);
    });

function log(req: Request, message: string) {
  console.log(`${new Date().toISOString()} [${req.requestId}] ${message}`);
}

export const FeedRouter: Router = router;
