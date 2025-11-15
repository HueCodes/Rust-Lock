package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Client struct {
	token  string
	org    string
	repo   string
	client *http.Client
}

func NewClient(token, org, repo string) *Client {
	return &Client{
		token:  token,
		org:    org,
		repo:   repo,
		client: &http.Client{},
	}
}

func (c *Client) GetQueuedWorkflowJobs(ctx context.Context) (int, error) {
	var url string
	if c.org != "" {
		url = fmt.Sprintf("https://api.github.com/orgs/%s/actions/runs?status=queued", c.org)
	} else {
		url = fmt.Sprintf("https://api.github.com/repos/%s/actions/runs?status=queued", c.repo)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		TotalCount int `json:"total_count"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	return result.TotalCount, nil
}
