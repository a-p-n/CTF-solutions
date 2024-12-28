package thirtytwo

import (
	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/util/random"
)

type Dealer struct {
	gsk   *share.PriPoly
	gpk   *share.PubPoly
}

func NewDealer(group kyber.Group, t int) *Dealer {
	sk := share.NewPriPoly(group, t, nil, random.New())
	pk := sk.Commit(group.Point().Base())
	return &Dealer{gsk: sk, gpk: pk}
}

func (d *Dealer) GetPubPoly() *share.PubPoly {
	return d.gpk
}

func (d *Dealer) GetPublicKey() kyber.Point {
	return d.gpk.Commit()
}

func (d *Dealer) DealShare(i dkg.Index) *share.PriShare {
	return d.gsk.Eval(int(i))
}
